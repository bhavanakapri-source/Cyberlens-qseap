import os

import gradio as gr
import spaces
from gradio import Server

import retrieval.query_embedder

from fastapi.middleware.cors import CORSMiddleware
from qdrant_client import QdrantClient

from database.connection import Base, engine
from database import models

from api.routes.auth import router as auth_router
from api.routes.query import router as query_router

from retrieval.query_pipeline import run_retrieval
from retrieval.context_builder import build_context

from llm.prompt_builder import build_prompt
from llm.gemini_client import generate_answer

from nvd.nvd_service import enrich_results_with_nvd


# ============================================================
# DATABASE
# ============================================================

Base.metadata.create_all(bind=engine)


# ============================================================
# GRADIO / FASTAPI SERVER
# ============================================================

api = Server(
    title="CyberLens API",
    description="AI-powered vulnerability analysis API",
    version="1.0.0",
)


# ============================================================
# CORS
# ============================================================

api.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# API ROUTES
# ============================================================

api.include_router(auth_router)
api.include_router(query_router)


# ============================================================
# HEALTH CHECK
# ============================================================

@api.get("/")
def root():
    return {
        "message": "CyberLens API is running."
    }


@api.get("/health")
def health():
    return {
        "status": "healthy"
    }


# ============================================================
# QDRANT
# ============================================================

QDRANT_URL = os.getenv("QDRANT_URL")
QDRANT_API_KEY = os.getenv("QDRANT_API_KEY")

if not QDRANT_URL:
    raise ValueError("QDRANT_URL is missing.")

if not QDRANT_API_KEY:
    raise ValueError("QDRANT_API_KEY is missing.")


qdrant_client = QdrantClient(
    url=QDRANT_URL,
    api_key=QDRANT_API_KEY,
)


# ============================================================
# CYBERLENS RAG FUNCTION
# ============================================================

@spaces.GPU
def cyberlens_query(user_query):

    if not user_query or not user_query.strip():
        return "Please enter a vulnerability query."

    try:
        # ----------------------------------------------------
        # STEP 1: RETRIEVE QUALYS / NESSUS RESULTS
        # ----------------------------------------------------

        retrieval_output = run_retrieval(
            client=qdrant_client,
            original_query=user_query,
            top_k_search=100,
            top_k_final=10,
        )

        results = retrieval_output["results"]

        # ----------------------------------------------------
        # STEP 2: BUILD ORIGINAL DATASET CONTEXT
        # ----------------------------------------------------

        context = build_context(
            results=results,
            max_results=10,
        )

        # ----------------------------------------------------
        # STEP 3: SUPPLEMENT WITH NVD EVIDENCE
        # ----------------------------------------------------

        try:
            nvd_response = enrich_results_with_nvd(
                results,
                user_query=user_query,
            )

        except Exception as exc:
            print(
                "[NVD] Enrichment failed:",
                type(exc).__name__,
                str(exc),
            )
            nvd_response = ""

        # ----------------------------------------------------
        # STEP 4: APPEND ONLY THE NVD EVIDENCE
        # ----------------------------------------------------

        start_marker = (
            "========== OPTIONAL NVD VERSION EVIDENCE =========="
        )
        end_marker = "========== END NVD EVIDENCE =========="

        if (
            isinstance(nvd_response, str)
            and start_marker in nvd_response
        ):
            nvd_evidence = nvd_response.split(
                start_marker, 1
            )[1]

            if end_marker in nvd_evidence:
                nvd_evidence = nvd_evidence.split(
                    end_marker, 1
                )[0]

            nvd_evidence = nvd_evidence.strip()

            if nvd_evidence:
                context = (
                    f"{context}\n\n"
                    f"{start_marker}\n"
                    f"{nvd_evidence}\n"
                    f"{end_marker}"
                )

                print("[NVD] Evidence appended to context.")

        # ----------------------------------------------------
        # STEP 5: BUILD GEMINI PROMPT
        # ----------------------------------------------------

        prompt = build_prompt(
            user_query=user_query,
            context=context,
        )

        print(
            "[NVD] Evidence included in Gemini prompt:",
            start_marker in prompt,
        )

        # ----------------------------------------------------
        # STEP 6: GENERATE ANSWER
        # ----------------------------------------------------

        answer = generate_answer(
            prompt=prompt
        )

        return answer

    except Exception as exc:
        print(
            "[CyberLens] Query failed:",
            type(exc).__name__,
            str(exc),
        )

        return f"CyberLens error: {str(exc)}"


# ============================================================
# GRADIO INTERFACE
# ============================================================

demo = gr.Interface(
    fn=cyberlens_query,

    inputs=gr.Textbox(
        label="Vulnerability Query",
        placeholder="Example: How can I fix CVE-1999-0455?",
        lines=3,
    ),

    outputs=gr.Markdown(
        label="CyberLens Analysis"
    ),

    title="CyberLens",

    description=(
        "AI-powered vulnerability analysis "
        "using Qdrant hybrid retrieval, NVD evidence, and Gemini."
    ),

    examples=[
        ["How can I fix CVE-1999-0455?"],
        ["What vulnerabilities affect Windows?"],
        ["How can I remediate this vulnerability?"],
    ],
)


# ============================================================
# MOUNT GRADIO INSIDE THE SERVER
# ============================================================

gr.mount_gradio_app(
    api,
    demo,
    path="/gradio",
    ssr_mode=False,
)


# ============================================================
# START
# ============================================================

if __name__ == "__main__":

    api.launch(
        server_name="0.0.0.0",
        server_port=7860,
        ssr_mode=False,
        show_error=True,
    )
