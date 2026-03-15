#!/usr/bin/env python3
"""Run a realistic agent workflow for overhead measurement."""
import os
import sys
import json
import time
import argparse

def run_workflow(results_dir: str, label: str, api_key: str):
    """Run a realistic agent workflow: read data, process, LLM call, write."""
    
    try:
        import numpy as np
    except ImportError:
        np = None
    
    print("Reading data files...")
    data = []
    for i in range(5):
        fname = f"/projects/shared/aegis/data/sample_{i}.hdf5"
        if os.path.exists(fname):
            with open(fname, "rb") as f:
                content = f.read()
            data.append(len(content))
        elif np:
            data.append(np.random.randn(1000, 64))
        else:
            data.append(list(range(1000)))
        time.sleep(0.1)
    
    print("Processing...")
    if np:
        result = float(np.mean([np.mean(d) if isinstance(d, np.ndarray) else d for d in data]))
    else:
        result = sum(d if isinstance(d, int) else len(d) for d in data) / len(data)
    time.sleep(0.5)
    
    print("Calling LLM...")
    if api_key:
        import urllib.request
        req = urllib.request.Request(
            "https://api.openai.com/v1/chat/completions",
            data=json.dumps({
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": f"Summarize: mean={result:.2f}"}],
                "max_tokens": 100
            }).encode(),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}"
            }
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                response = json.loads(resp.read())
            print(f"LLM response received: {len(json.dumps(response))} bytes")
        except Exception as e:
            print(f"LLM call failed: {e}")
    else:
        print("No API key, simulating LLM call...")
        time.sleep(1.0)
    
    print("Writing results...")
    os.makedirs(results_dir, exist_ok=True)
    with open(f"{results_dir}/agent-results-{label}.json", "w") as f:
        json.dump({"mean": result, "samples": len(data)}, f)
    
    print("Done.")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--results-dir", required=True)
    parser.add_argument("--label", required=True)
    parser.add_argument("--api-key", default="")
    args = parser.parse_args()
    
    run_workflow(args.results_dir, args.label, args.api_key)

if __name__ == "__main__":
    main()
