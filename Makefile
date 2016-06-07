REBAR ?= rebar

.PHONY: test 

compile:
	@$(REBAR) compile

clean:
	@$(REBAR) clean

test:
	@$(REBAR) as test do xref,eunit

dialyzer:
	@$(REBAR) dialyzer

shell:
	@$(REBAR) shell
