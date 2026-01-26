
import os
import subprocess

if __name__ == "__main__":
    cmd = ["claude", '-p', "Use the 'ai-infra-module-modeler' skill to analyze the module structure of /mnt/raid/home/dongtian/vuln/data/repos/LLaMA-Factory and write outputs to the folder /home/dongtian/vuln/llm-vulvariant/analysis-cc"]
    result = subprocess.run(
        cmd,
        check=True,
        capture_output=True,
        text=True,
    )