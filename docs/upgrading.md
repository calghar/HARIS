# Upgrading

## LiteLLM backend names

Copy the SQLite database file before you upgrade. Migration `0009_llm_backend_names` runs on the first start of the new version.

The migration sets the LLM backend of every saved scan config template named `anthropic`, `openai`, `ollama` or `bedrock` to `litellm`. Templates with an empty backend or `litellm` stay as they are. Scans and reports are not changed.

The migration is one-way. Its rollback does nothing, and the old backend names cannot be restored without the copy of the database file.

HARIS rejects the names `anthropic`, `openai`, `ollama` and `bedrock` as an LLM backend from this version on. The CLI exits with code 3. The web API answers with status 400. Use `litellm` and set the provider in the model name.
