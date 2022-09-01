#!/bin/sh
dasel delete -p toml -f Cargo.lock '.package.(name=vade-sidetree)'
dasel delete -p toml -f Cargo.lock '.package.(name=vade-signer)'
