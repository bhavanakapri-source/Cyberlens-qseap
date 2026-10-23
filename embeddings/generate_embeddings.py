from pathlib import Path
import gc
import time

import numpy as np
import pandas as pd
import torch
from sentence_transformers import SentenceTransformer


# ============================================================
# CONFIG
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[1]

PLUGIN_INPUT_DIR = PROJECT_ROOT / "data" / "embedding_ready" / "plugins"
QUALYS_INPUT_DIR = PROJECT_ROOT / "data" / "embedding_ready" / "qualys"

OUTPUT_DIR = PROJECT_ROOT / "data" / "embeddings"

MODEL_NAME = "paraphrase-multilingual-MiniLM-L12-v2"

# Safe starting value for RTX 3050 6GB
BATCH_SIZE = 64

# Process CSV in chunks so RAM stays under control
CSV_CHUNK_SIZE = 5000


# ============================================================
# DEVICE
# ============================================================

DEVICE = "cuda" if torch.cuda.is_available() else "cpu"


def print_gpu_info():
    print("=" * 70)
    print("VULNERABILITY RAG - EMBEDDING GENERATION")
    print("=" * 70)

    print(f"\nDevice: {DEVICE}")

    if torch.cuda.is_available():
        print(f"GPU: {torch.cuda.get_device_name(0)}")
        print(f"CUDA: {torch.version.cuda}")

    print(f"Model: {MODEL_NAME}")
    print(f"Batch size: {BATCH_SIZE}")
    print(f"CSV chunk size: {CSV_CHUNK_SIZE}")

    print("=" * 70)


# ============================================================
# LOAD MODEL
# ============================================================

def load_model():
    print("\nLoading Sentence Transformer model...")

    start = time.time()

    model = SentenceTransformer(
        MODEL_NAME,
        device=DEVICE
    )

    elapsed = time.time() - start

    print(f"Model loaded in {elapsed:.2f} seconds")

    return model


# ============================================================
# PROCESS ONE CSV
# ============================================================

def process_file(model, input_file, output_file):

    print("\n" + "-" * 70)
    print(f"Processing: {input_file.name}")
    print("-" * 70)

    start_time = time.time()

    # Read the file
    df = pd.read_csv(
        input_file,
        dtype=str,
        keep_default_na=False
    )

    total_rows = len(df)

    print(f"Records: {total_rows:,}")

    texts = df["embedding_text"].tolist()

    all_embeddings = []

    # Process in smaller chunks
    for start in range(0, total_rows, CSV_CHUNK_SIZE):

        end = min(start + CSV_CHUNK_SIZE, total_rows)

        chunk_texts = texts[start:end]

        print(
            f"Encoding records "
            f"{start + 1:,} - {end:,} / {total_rows:,}",
            end="\r"
        )

        embeddings = model.encode(
            chunk_texts,
            batch_size=BATCH_SIZE,
            show_progress_bar=False,
            convert_to_numpy=True,
            normalize_embeddings=True
        )

        all_embeddings.append(embeddings.astype(np.float32))

    print()

    embeddings = np.concatenate(all_embeddings, axis=0)

    # Save only vectors
    output_file.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    np.save(output_file, embeddings)

    elapsed = time.time() - start_time

    print(f"Embedding shape: {embeddings.shape}")
    print(f"Saved: {output_file}")
    print(f"Time: {elapsed / 60:.2f} minutes")

    # Free memory
    del df
    del texts
    del all_embeddings
    del embeddings

    gc.collect()

    if torch.cuda.is_available():
        torch.cuda.empty_cache()


# ============================================================
# PROCESS DATASET
# ============================================================

def process_dataset(model, input_dir, output_dir, prefix):

    files = sorted(
        input_dir.glob(f"{prefix}_part_*.csv")
    )

    print("\n")
    print("=" * 70)
    print(f"{prefix.upper()} EMBEDDING GENERATION")
    print("=" * 70)

    print(f"Files found: {len(files)}")

    for index, input_file in enumerate(files, start=1):

        output_file = (
            output_dir /
            f"{input_file.stem}.npy"
        )

        print(
            f"\n[{index}/{len(files)}]"
        )

        # Resume support
        if output_file.exists():

            print(
                f"Already exists, skipping: "
                f"{output_file.name}"
            )

            continue

        process_file(
            model,
            input_file,
            output_file
        )


# ============================================================
# MAIN
# ============================================================

def main():

    print_gpu_info()

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    model = load_model()

    # --------------------------------------------------------
    # PLUGINS
    # --------------------------------------------------------

    process_dataset(
        model,
        PLUGIN_INPUT_DIR,
        OUTPUT_DIR / "plugins",
        "plugins"
    )

    # --------------------------------------------------------
    # QUALYS
    # --------------------------------------------------------

    process_dataset(
        model,
        QUALYS_INPUT_DIR,
        OUTPUT_DIR / "qualys",
        "qualys"
    )

    print("\n")
    print("=" * 70)
    print("EMBEDDING GENERATION COMPLETED")
    print("=" * 70)

    print("\nExpected:")
    print("Plugins: 311,302 embeddings")
    print("Qualys:  389,817 embeddings")
    print("Total:   701,119 embeddings")

    print("\nOutput:")
    print(OUTPUT_DIR)

    print("=" * 70)


if __name__ == "__main__":
    main()