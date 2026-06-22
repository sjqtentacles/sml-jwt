# sml-jwt build
MLTON      ?= mlton
BIN        := bin
LIBDIR     := lib/github.com/sjqtentacles/sml-jwt
VENDOR     := lib/github.com/sjqtentacles
TEST_MLB   := test/sources.mlb
SRCS       := $(wildcard $(LIBDIR)/*.sml $(LIBDIR)/*.sig) \
              $(wildcard $(VENDOR)/sml-codec/*.sml $(VENDOR)/sml-codec/*.sig) \
              $(wildcard $(VENDOR)/sml-crypto/*.sml $(VENDOR)/sml-crypto/*.sig) \
              $(wildcard $(VENDOR)/sml-json/*.sml) \
              $(wildcard $(VENDOR)/sml-parsec/*.sml $(VENDOR)/sml-parsec/*.sig) \
              $(wildcard test/*.sml) $(TEST_MLB) \
              $(LIBDIR)/sources.mlb $(VENDOR)/sml-codec/sources.mlb \
              $(VENDOR)/sml-crypto/sources.mlb $(VENDOR)/sml-json/sources.mlb \
              $(VENDOR)/sml-parsec/parsec.mlb

.PHONY: all test poly test-poly all-tests example clean

all: $(BIN)/test-mlton

$(BIN)/test-mlton: $(SRCS) | $(BIN)
	$(MLTON) -output $@ $(TEST_MLB)

test: $(BIN)/test-mlton
	$(BIN)/test-mlton

poly: $(BIN)/test-poly

$(BIN)/test-poly: $(SRCS) tools/polybuild | $(BIN)
	sh tools/polybuild -o $@ $(TEST_MLB)

test-poly: $(BIN)/test-poly
	$(BIN)/test-poly

all-tests: test test-poly

example: $(BIN)/demo
	./$(BIN)/demo

$(BIN)/demo: $(SRCS) examples/demo.sml examples/sources.mlb | $(BIN)
	$(MLTON) -output $@ examples/sources.mlb

$(BIN):
	mkdir -p $(BIN)

clean:
	rm -rf $(BIN)
