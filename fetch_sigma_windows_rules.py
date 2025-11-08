import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
import yaml

SIGMA_GIT = "https://github.com/SigmaHQ/sigma.git"
OUT_DIR = Path.cwd() / "sigma_rules"
CLONE_DIR_PREFIX = "sigma_repo_"

def run_cmd(cmd, cwd=None):
    try:
        res = subprocess.run(cmd, shell=False, cwd=cwd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return res.stdout
    except subprocess.CalledProcessError as e:
        print(f"Command failed: {' '.join(cmd)}")
        print("stdout:", e.stdout)
        print("stderr:", e.stderr)
        raise

def is_windows_rule_yaml(yaml_obj, file_path_str):
    """
    Decide whether a loaded YAML object is a Windows-targeted Sigma rule.
    YAML object is typically a dict containing keys like 'logsource' and 'detection'.
    We'll check:
      - logsource.product == 'windows' OR
      - logsource.category contains common windows strings OR
      - file path contains '/windows/' (fallback)
    """
    try:
        if not isinstance(yaml_obj, dict):
            return False
        logsource = yaml_obj.get("logsource") or {}
        product = logsource.get("product")
        category = logsource.get("category", "")
        if product and isinstance(product, str) and product.strip().lower() == "windows":
            return True
        # sometimes product may be nested or list; be lenient
        if isinstance(product, (list, tuple)) and any(str(p).lower() == "windows" for p in product):
            return True
        # fallback: look at category or file path
        if isinstance(category, str) and ("process" in category.lower() or "authentication" in category.lower() or "windows" in category.lower()):
            return True
    except Exception:
        pass
    # finally use path heuristic
    if "/windows/" in file_path_str.replace("\\", "/").lower():
        return True
    return False

def main():
    print("➡️  Fetching Sigma rules (Windows) from GitHub...")
    tmp_dir = Path(tempfile.mkdtemp(prefix=CLONE_DIR_PREFIX))
    try:
        # shallow clone, single branch
        print(f"Cloning {SIGMA_GIT} into {tmp_dir} (shallow clone)...")
        run_cmd(["git", "clone", "--depth", "1", SIGMA_GIT, str(tmp_dir)])
    except Exception as e:
        print("❌ Git clone failed. Ensure 'git' is installed and you have network access.")
        shutil.rmtree(tmp_dir, ignore_errors=True)
        sys.exit(1)

    try:
        # ensure output dir exists
        OUT_DIR.mkdir(parents=True, exist_ok=True)

        total_files = 0
        saved_files = 0

        # walk repo for .yml/.yaml files
        for path in tmp_dir.rglob("*.yml"):
            total_files += 1
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
                # Some files may contain multiple YAML documents separated by '---'
                docs = list(yaml.safe_load_all(text))
            except Exception:
                # skip YAMLs we cannot parse
                continue

            saved_any_doc = False
            for idx, doc in enumerate(docs):
                if doc is None:
                    continue
                try:
                    if is_windows_rule_yaml(doc, str(path)):
                        # save the original file (or only matched doc)
                        # If file contains single document, write directly. If multiple docs, write numbered files.
                        if len(docs) == 1:
                            dest_name = OUT_DIR / path.name
                            # avoid overwriting same filename: if exists, append numeric suffix
                            if dest_name.exists():
                                base = dest_name.stem
                                suffix = dest_name.suffix
                                i = 1
                                while (OUT_DIR / f"{base}_{i}{suffix}").exists():
                                    i += 1
                                dest_name = OUT_DIR / f"{base}_{i}{suffix}"
                            dest_name.write_text(text, encoding="utf-8")
                            saved_files += 1
                            saved_any_doc = True
                        else:
                            # write only this document portion
                            doc_text = yaml.safe_dump(doc, sort_keys=False, allow_unicode=True)
                            dest_name = OUT_DIR / f"{path.stem}_doc{idx+1}{path.suffix}"
                            dest_name.write_text(doc_text, encoding="utf-8")
                            saved_files += 1
                            saved_any_doc = True
                        # We keep scanning multdocs in case more than one doc matches.
                except Exception:
                    continue

        print(f"✅ Done. Scanned {total_files} .yml files, saved {saved_files} windows-targeted rules into '{OUT_DIR.resolve()}'")
        if saved_files == 0:
            print("⚠️ No Windows rules found by heuristics. You can inspect the repo manually or broaden heuristics.")
        else:
            print("ℹ️ You can now run your consumer; it will load rules from ./sigma_rules/")
    finally:
        # clean up cloned repo
        try:
            shutil.rmtree(tmp_dir)
        except Exception:
            pass

if __name__ == "__main__":
    main()
