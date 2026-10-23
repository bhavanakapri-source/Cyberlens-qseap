import spaces
import torch

from sentence_transformers import SentenceTransformer


MODEL_NAME = "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2"

DEVICE = "cuda" if torch.cuda.is_available() else "cpu"

print(f"Loading embedding model on: {DEVICE}")

model = SentenceTransformer(
    MODEL_NAME,
    device=DEVICE,
)


@spaces.GPU(duration=120)
def embed_query(query: str):
    """
    Convert the user's query into a 384-dimensional
    normalized embedding vector.
    """

    embedding = model.encode(
        query,
        normalize_embeddings=True,
    )

    return embedding.tolist()