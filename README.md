# 通用工具 source release 草稿

這份 bundle 供 `vine53/vine-governance-policy` 發布前審查，目前不能發布：通用 library 與 tests 必須先通過獨立隱私審查，並與已指定精確路徑的 workflow 一同凍結，記錄 source 與 bundle SHA256。

公開範圍僅含通用 policy／runner／verifier 純函式、限定測試及核准的公開簽發 metadata。禁止放入應用 business code、候選 private checkout、agent catalogue、credentials、customer data，或可任意指定候選 source 的輸入。應用 repository 保持 private。

`policy-check.yml` 以 GitHub-hosted runner 跑通用測試，check context 為 `generic-policy-check`。工具 bootstrap 採已核准的 required PR、strict check、enforce admins、approvals 0、禁止 force push 與 branch deletion；`required_pull_request_reviews` 必須是核准數為 0 的物件，不能用 null 取消 required PR。這個策略僅用於通用工具 bootstrap，不代表應用程式的正式 review 已完成。

空 repository 只允許以已審查 README 建立最初的 main commit。其餘 workflow、通用 library 與測試必須先提交到唯一外部 PR branch `codex/bootstrap-generic-tool`，建立 PR 到 main。觀測該 PR 的真實 `generic-policy-check` 成功及實際 GitHub App ID 後，先設定並讀回上述 main 保護，再以精確 PR head SHA 合併。不得在設定保護前直接將其餘檔案更新到 main。這個外部 PR branch 不需要本地 checkout／branch／worktree，且不自動刪除。

若第一次 PR 的 workflow 無法觸發、check 不通過、branch protection 回 422／403，或前置 SHA 漂移，須保存證據並停止；不得建立空測試、偽造 status、降低保護或直接合併。PR 合併後還須觀測 main 的真實 check 通過，才可手動執行 source release。

`source-release.yml` 僅可手動觸發受保護 main 的精確 commit，沒有自由 source／ref／私有 repository 輸入；純檢查 job 只有 contents:read，簽發 job 才具 id-token:write 與 attestations:write。

使用標準 `actions/attest` 產生 build provenance，以 `gh attestation verify` 核對 GitHub OIDC signer／issuer、受保護 workflow 的不可變 digest、source commit 與 artifact subject，並拒絕非預期或 self-hosted runner。所有實際驗證 identity／digest 須由核准的 release 記錄提供，不能使用此草稿中的 placeholder 或自行簽名。

這個 artifact 只能稱為 **VERIFIED_TOOL_RELEASE**。它不代表完整 policy、application admission、review GO、gland 准入或 private 應用 branch required check 已成立。標準 attestation 只證明工具 release 的 provenance；FR-GH-075 的完整 scope、逐軸 GO、期限、撤銷、獨立 verifier 與 application exact required check 仍須分別驗收。

此草稿本身不修改 repository、發布 source 或觸發 workflow。既有空 repo 的 Actions allowlist 與 SHA pinning 已另有讀回回執；此 bundle 不重複設定。完成 library／privacy／workflow syntax 審查並記錄最終五檔雜湊後，才可交由 root 明確授予的 freeze 包沿上述 API／PR 流程發布。
