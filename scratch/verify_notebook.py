import asyncio
import json
import sys
import traceback

path = "/Users/edcher/Documents/GitHub/trust_chain/examples/trustchain_tutorial.ipynb"
with open(path) as f:
    nb = json.load(f)

# Shared globals dictionary to simulate cell persistent state
globals_dict = {"__name__": "__main__"}

for idx, cell in enumerate(nb.get("cells", [])):
    if cell.get("cell_type") == "code":
        source_lines = cell.get("source", [])
        # Filter out lines starting with '!' (shell commands like pip install)
        filtered_lines = [
            line for line in source_lines if not line.strip().startswith("!")
        ]
        source = "".join(filtered_lines)

        if not source.strip():
            continue

        try:
            print(f"Executing cell {idx}...")
            exec(source, globals_dict)
            print(f"Cell {idx} SUCCESS")
        except SyntaxError as se:
            if "outside function" in str(se):
                print(f"Cell {idx} has top-level await. Wrapping in async function...")
                lines = source.splitlines()
                indented_code = "\n".join("    " + line for line in lines)
                wrapper_code = f"async def __run_cell_async():\n{indented_code}\n"
                try:
                    exec(wrapper_code, globals_dict)

                    # Manage event loop properly across Python versions
                    try:
                        loop = asyncio.get_running_loop()
                    except RuntimeError:
                        loop = asyncio.new_event_loop()
                        asyncio.set_event_loop(loop)

                    if loop.is_running():
                        future = asyncio.run_coroutine_threadsafe(
                            globals_dict["__run_cell_async"](), loop
                        )
                        future.result()
                    else:
                        loop.run_until_complete(globals_dict["__run_cell_async"]())
                    print(f"Cell {idx} SUCCESS (Async wrapped)")
                except Exception as async_err:
                    print(f"Error in cell {idx} (Async wrapped): {async_err}")
                    traceback.print_exc()
                    sys.exit(1)
            else:
                print(f"SyntaxError in cell {idx}: {se}")
                traceback.print_exc()
                sys.exit(1)
        except Exception as e:
            print(f"Error in cell {idx}: {e}")
            traceback.print_exc()
            sys.exit(1)
print("All cells executed successfully!")
