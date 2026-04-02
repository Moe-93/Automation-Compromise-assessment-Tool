import os
import shutil
import subprocess
import time

def _collect_windows_artifact(self, name, config, base_dir):
    dest_path = os.path.join(base_dir, config.get("dest", f"{name}.txt"))
    os.makedirs(os.path.dirname(dest_path), exist_ok=True)

    try:
        artifact_type = config.get("type")

        if artifact_type == "file":
            source_path = config.get("path")

            if source_path and os.path.exists(source_path):
                if self._copy_with_retry(source_path, dest_path):
                    self.collected_files.append(dest_path)
                    self.log_activity(f"Collected {name}: {source_path}")
                else:
                    self.log_activity(f"Failed after retries: {name}", "WARNING")

            else:
                alt_path = config.get("alt_path")

                if alt_path and os.path.exists(alt_path):
                    if self._copy_with_retry(alt_path, dest_path):
                        self.collected_files.append(dest_path)
                        self.log_activity(f"Collected {name} (alt): {alt_path}")
                else:
                    self.log_activity(f"Source not found: {name}", "WARNING")

        elif artifact_type == "command":
            command = config.get("command")

            if command:
                try:
                    result = subprocess.run(
                        command,
                        shell=True,
                        capture_output=True,
                        text=True,
                        timeout=60
                    )

                    with open(dest_path, "w", encoding="utf-8") as f:
                        f.write(result.stdout)

                    self.collected_files.append(dest_path)
                    self.log_activity(f"Executed command: {name}")

                except subprocess.TimeoutExpired:
                    self.log_activity(f"Timeout: {name}", "WARNING")

                except Exception as e:
                    self.log_activity(f"Command failed {name}: {str(e)}", "ERROR")

    except Exception as e:
        self.log_activity(f"Unexpected error {name}: {str(e)}", "ERROR")


def _copy_with_retry(self, src, dst, retries=3):
    for _ in range(retries):
        try:
            shutil.copy2(src, dst)
            return True
        except PermissionError:
            time.sleep(1)
        except Exception:
            time.sleep(1)

    return False
