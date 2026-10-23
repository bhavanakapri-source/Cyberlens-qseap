import os
import re

import spaces
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from qdrant_client import QdrantClient
from sqlalchemy.orm import Session

from database.connection import get_db
from database.crud import (
    add_message,
    create_conversation,
    get_conversation,
    get_conversations,
    get_messages,
)
from database.models import User
from api.auth import get_current_user

from retrieval.query_pipeline import run_retrieval
from retrieval.context_builder import build_context

from llm.prompt_builder import build_prompt
from llm.gemini_client import generate_answer

from nvd.nvd_service import enrich_results_with_nvd


# ============================================================
# ROUTER
# ============================================================

router = APIRouter(
    prefix="/api",
    tags=["CyberLens"],
)


# ============================================================
# QDRANT CLOUD
# ============================================================

QDRANT_URL = os.getenv("QDRANT_URL")
QDRANT_API_KEY = os.getenv("QDRANT_API_KEY")

if not QDRANT_URL:
    raise ValueError(
        "QDRANT_URL is missing from environment variables."
    )

if not QDRANT_API_KEY:
    raise ValueError(
        "QDRANT_API_KEY is missing from environment variables."
    )

qdrant_client = QdrantClient(
    url=QDRANT_URL,
    api_key=QDRANT_API_KEY,
)


# ============================================================
# REQUEST / RESPONSE MODELS
# ============================================================

class QueryRequest(BaseModel):
    query: str
    conversation_id: int | None = None


class QueryResponse(BaseModel):
    conversation_id: int
    query: str
    answer: str


class ConversationResponse(BaseModel):
    id: int
    title: str


class MessageResponse(BaseModel):
    id: int
    role: str
    content: str


# ============================================================
# GPU RETRIEVAL
# ============================================================

@spaces.GPU(duration=120)
def run_gpu_retrieval(user_query: str):
    return run_retrieval(
        client=qdrant_client,
        original_query=user_query,
        top_k_search=100,
        top_k_final=10,
    )


# ============================================================
# QUERY ENDPOINT
# ============================================================

@router.post(
    "/query",
    response_model=QueryResponse,
)
def query(
    request: QueryRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # --------------------------------------------------------
    # VALIDATE QUERY
    # --------------------------------------------------------

    user_query = request.query.strip()

    if not user_query:
        raise HTTPException(
            status_code=400,
            detail="Query cannot be empty.",
        )

    # --------------------------------------------------------
    # GET OR CREATE CONVERSATION
    # --------------------------------------------------------

    conversation_id = request.conversation_id

    if conversation_id is None:
        conversation = create_conversation(
            db=db,
            user_id=current_user.id,
            title=user_query[:80],
        )
        conversation_id = conversation.id

    else:
        conversation = get_conversation(
            db=db,
            conversation_id=conversation_id,
            user_id=current_user.id,
        )

        if conversation is None:
            raise HTTPException(
                status_code=404,
                detail="Conversation not found.",
            )

    # --------------------------------------------------------
    # SAVE USER MESSAGE
    # --------------------------------------------------------

    add_message(
        db=db,
        conversation_id=conversation_id,
        role="user",
        content=user_query,
    )

    # --------------------------------------------------------
    # ORIGINAL QUALYS / NESSUS RETRIEVAL
    # --------------------------------------------------------

    retrieval_output = run_gpu_retrieval(user_query)
    results = retrieval_output["results"]

    # Build the original dataset context first.
    # This context remains the primary evidence.

    context = build_context(
        results=results,
        max_results=10,
    )

    print("\n========== CYBERLENS RETRIEVAL ==========")
    print("User query:", user_query)
    print("Retrieved result count:", len(results))
    print("Original context length:", len(context))
    print("=========================================\n")

    # --------------------------------------------------------
    # OPTIONAL NVD ENRICHMENT
    # --------------------------------------------------------

    # NVD enrichment must not prevent the original RAG answer
    # from being generated if an external lookup fails.

    try:
        nvd_response = enrich_results_with_nvd(
            results,
            user_query=user_query,
        )

        print("DIRECT CVE IN QUERY:", user_query)
        print(
            "REQUESTED CVE IN NVD RESPONSE:",
            bool(
                re.search(
                    r"CVE-2020-11749",
                    nvd_response,
                    re.IGNORECASE,
                )
            ),
        )

        if not isinstance(nvd_response, str):
            print(
                "NVD enrichment returned an unexpected type:",
                type(nvd_response).__name__,
            )
            nvd_response = ""

    except Exception as exc:
        print(
            "Optional NVD enrichment failed:",
            type(exc).__name__,
            str(exc),
        )
        nvd_response = ""

    # --------------------------------------------------------
    # EXTRACT ONLY THE SUPPLEMENTAL NVD EVIDENCE
    # --------------------------------------------------------

    nvd_start_marker = (
        "========== OPTIONAL NVD VERSION EVIDENCE =========="
    )
    nvd_end_marker = "========== END NVD EVIDENCE =========="

    if nvd_response:
        print("\n========== NVD ENRICHMENT ==========")
        print("NVD response length:", len(nvd_response))

        if nvd_start_marker in nvd_response:
            nvd_evidence = nvd_response.split(
                nvd_start_marker,
                1,
            )[1]

            if nvd_end_marker in nvd_evidence:
                nvd_evidence = nvd_evidence.split(
                    nvd_end_marker,
                    1,
                )[0]

            nvd_evidence = nvd_evidence.strip()

            if nvd_evidence:
                # Append only the NVD evidence. Do not append
                # the original dataset records a second time.
                context = (
                    f"{context}\n\n"
                    f"{nvd_start_marker}\n"
                    f"{nvd_evidence}\n"
                    f"{nvd_end_marker}"
                )

                print("NVD evidence appended to Gemini context.")
            else:
                print("NVD evidence section was empty.")

        else:
            print(
                "NVD response did not contain the expected "
                "evidence marker. Nothing was appended."
            )

        print("===================================\n")

    else:
        print(
            "NVD returned no response. "
            "Continuing with the original dataset context."
        )

    # --------------------------------------------------------
    # BUILD GEMINI PROMPT
    # --------------------------------------------------------

    prompt = build_prompt(
        user_query=user_query,
        context=context,
    )

    # --------------------------------------------------------
    # VERIFY CONTEXT BEFORE SENDING TO GEMINI
    # --------------------------------------------------------

    print("\n========== GEMINI PROMPT CHECK ==========")
    print("Prompt length:", len(prompt))
    print(
        "Contains NVD evidence section:",
        nvd_start_marker in prompt,
    )
    print(
        "Contains requested CVE:",
        any(
            cve in prompt.upper()
            for cve in (
                "CVE-2021-36934",
                "CVE-2020-11749",
            )
            if cve in user_query.upper()
        ),
    )
    print("=========================================\n")

    # --------------------------------------------------------
    # GENERATE ANSWER
    # --------------------------------------------------------

    answer = generate_answer(
        prompt=prompt,
    )

    # --------------------------------------------------------
    # SAVE ASSISTANT MESSAGE
    # --------------------------------------------------------

    add_message(
        db=db,
        conversation_id=conversation_id,
        role="assistant",
        content=answer,
    )

    # --------------------------------------------------------
    # RESPONSE
    # --------------------------------------------------------

    return QueryResponse(
        conversation_id=conversation_id,
        query=user_query,
        answer=answer,
    )


# ============================================================
# GET ALL USER CONVERSATIONS
# ============================================================

@router.get(
    "/conversations",
    response_model=list[ConversationResponse],
)
def conversations(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return get_conversations(
        db=db,
        user_id=current_user.id,
    )


# ============================================================
# GET CONVERSATION MESSAGES
# ============================================================

@router.get(
    "/conversations/{conversation_id}/messages",
    response_model=list[MessageResponse],
)
def conversation_messages(
    conversation_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    conversation = get_conversation(
        db=db,
        conversation_id=conversation_id,
        user_id=current_user.id,
    )

    if conversation is None:
        raise HTTPException(
            status_code=404,
            detail="Conversation not found.",
        )

    return get_messages(
        db=db,
        conversation_id=conversation_id,
    )