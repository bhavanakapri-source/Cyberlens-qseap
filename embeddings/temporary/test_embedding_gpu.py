from sentence_transformers import SentenceTransformer
import torch
import time


MODEL_NAME = "paraphrase-multilingual-MiniLM-L12-v2"


print("=" * 70)
print("VULNERABILITY RAG - GPU EMBEDDING TEST")
print("=" * 70)

print(f"\nPyTorch: {torch.__version__}")
print(f"CUDA available: {torch.cuda.is_available()}")

if torch.cuda.is_available():
    print(f"GPU: {torch.cuda.get_device_name(0)}")
    device = "cuda"
else:
    print("WARNING: CUDA unavailable. Using CPU.")
    device = "cpu"


print(f"Device selected: {device}")

print("\nLoading model...")
start = time.time()

model = SentenceTransformer(
    MODEL_NAME,
    device=device
)

load_time = time.time() - start

print(f"Model loaded successfully in {load_time:.2f} seconds")


# Small test batch
test_texts = [
    "Remote attacker can exploit a vulnerability to read arbitrary files.",
    "The vulnerability affects the remote application server.",
    "Apply the vendor security patch to remediate the vulnerability.",
    "DNS host name information was gathered from the remote system.",
    "This vulnerability has a high security risk."
]

print(f"\nEncoding {len(test_texts)} test records...")

start = time.time()

embeddings = model.encode(
    test_texts,
    batch_size=5,
    convert_to_tensor=True,
    normalize_embeddings=True,
    show_progress_bar=False
)

encode_time = time.time() - start


print(f"Encoding completed in {encode_time:.2f} seconds")

print("\n" + "=" * 70)
print("EMBEDDING RESULTS")
print("=" * 70)

print(f"Tensor shape: {embeddings.shape}")
print(f"Embedding dimension: {embeddings.shape[1]}")
print(f"Data type: {embeddings.dtype}")
print(f"Device: {embeddings.device}")

print(f"\nContains NaN: {torch.isnan(embeddings).any().item()}")
print(f"Contains Inf: {torch.isinf(embeddings).any().item()}")

print("\nFirst embedding (first 10 values):")
print(embeddings[0][:10].detach().cpu().numpy())

print("\n" + "=" * 70)

if (
    embeddings.shape[1] == 384
    and not torch.isnan(embeddings).any()
    and not torch.isinf(embeddings).any()
    and str(embeddings.device).startswith("cuda")
):
    print("✓ MODEL TEST: PASS")
    print("✓ GPU INFERENCE: PASS")
    print("✓ EMBEDDING DIMENSION: 384")
    print("✓ NO NaN VALUES")
    print("✓ NO Inf VALUES")
    print("\nREADY FOR FULL EMBEDDING GENERATION.")
else:
    print("✗ EMBEDDING TEST FAILED")
    print("Check the results above.")

print("=" * 70)