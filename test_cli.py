from trustchain import TrustChain, TrustChainConfig

tc = TrustChain(
    TrustChainConfig(enable_chain=True, chain_storage="file", chain_dir=".trustchain")
)
sig = tc.sign("bash_tool", {"command": "rm -rf /"}, parent_signature=None)
op_id = tc.chain.log()[0]["id"]
print("Signed op id:", op_id)
tc.revert(op_id, "Bad agent!")
