# Component
build: components index.js
	@component build --dev
components: component.json
	@component install --dev
clean:
	rm -fr build components template.js

# Tests
test:
	@node node_modules/lab/bin/lab
test-cov: 
	@node node_modules/lab/bin/lab -r threshold -t 100
test-cov-html:
	@node node_modules/lab/bin/lab -r html -o coverage.html
complexity:
	@node node_modules/complexity-report/src/cli.js -o complexity.md -f markdown lib

.PHONY: test test-cov test-cov-html complexity clean