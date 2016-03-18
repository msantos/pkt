REBAR = $(shell which rebar3 || echo ./rebar3)

.PHONY: test

compile:
	@$(REBAR) compile

clean:
	@$(REBAR) clean

test:
	@$(REBAR) as test do xref,eunit

dialyzer:
	@$(REBAR) dialyzer
