#!/bin/bash
go clean -cache
go clean -testcache
echo "Go build cache and test cache have been cleaned."
