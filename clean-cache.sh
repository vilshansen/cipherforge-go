#!/bin/bash
go clean -cache
go clean -testcache
go clean -modcache
echo "Go cache, test cache, and module cache have been cleaned."
