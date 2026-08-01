# Clean Go build and test caches (Windows PowerShell)
go clean -cache
go clean -testcache
Write-Host "Go build cache and test cache have been cleaned."
