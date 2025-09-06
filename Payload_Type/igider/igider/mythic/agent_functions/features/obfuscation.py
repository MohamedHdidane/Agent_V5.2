from __future__ import annotations
import re, base64, random, sys, os, ast, keyword, tokenize, io, hashlib, zlib, codecs, textwrap
from typing import Dict, List, Set, Tuple, Optional
import string
from itertools import cycle

def generate_random_identifier(length: int = 8) -> str:
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(length))

def basic_obfuscate(code: str) -> str:
    key = hashlib.md5(os.urandom(128)).hexdigest().encode()
    encrypted_content = ''.join(chr(c ^ k) for c, k in zip(code.encode(), cycle(key))).encode()
    b64_enc_content = base64.b64encode(encrypted_content)

    var_b64 = generate_random_identifier()
    var_key = generate_random_identifier()
    var_iter = generate_random_identifier()

    return f"""import base64, itertools
{var_b64} = {b64_enc_content}
{var_key} = {key}
{var_iter} = itertools.cycle({var_key})
exec(''.join(chr(c ^ k) for c, k in zip(base64.b64decode({var_b64}), {var_iter})).encode())
"""



def advanced_obfuscate(code: str) -> str:
    """Fully obfuscate Python code string using all transformations and exec-wrap (3 layers)."""

    # ------------- Helper utilities -------------
    builtin_names = set(dir(__builtins__)) | set(keyword.kwlist)
    used_names: Set[str] = set()
    name_mapping: Dict[str, str] = {}
    safe_to_rename: Set[str] = set()
    imports_to_add: Set[str] = set()

    def generate_random_name(length=8, prefix=""):
        attempts = 0
        while attempts < 100:
            if prefix:
                first_char = prefix[0] if prefix[0].isalpha() else 'O'
                rest_chars = ''.join(random.choices('O0Il1_', k=max(1, length-1)))
            else:
                first_char = random.choice('OIl')
                rest_chars = ''.join(random.choices('O0Il1_', k=max(1, length-1)))
            name = first_char + rest_chars
            if (not keyword.iskeyword(name)
                and name not in builtin_names
                and name not in used_names
                and name not in name_mapping.values()):
                used_names.add(name)
                return name
            attempts += 1
        return f"O{random.randint(1000,9999)}"

    def ensure_imports(content: str) -> str:
        for stmt in sorted(imports_to_add):
            mod = stmt.split()[1]
            if not any(line.strip().startswith(("import " + mod, "from " + mod))
                       for line in content.splitlines()):
                # insert after imports
                lines = content.splitlines()
                pos = 0
                for i, line in enumerate(lines):
                    if line.strip().startswith(("import ", "from ")):
                        pos = i + 1
                    elif line.strip() and not line.strip().startswith("#"):
                        break
                lines.insert(pos, stmt)
                content = "\n".join(lines)
        return content

    def validate(content: str) -> bool:
        try:
            ast.parse(content)
            return True
        except SyntaxError:
            return False

    # ------------- String obfuscation -------------
    def encode_string_expr(s: str) -> Optional[str]:
        if len(s) < 2 or len(s) > 500:
            return None
        method = random.choice(['base64','hex','zlib','reverse'])
        try:
            if method == "base64":
                enc = base64.b64encode(s.encode()).decode()
                imports_to_add.add("import base64")
                # Use parentheses to make it a valid expression
                return f'(__import__("base64").b64decode("{enc}").decode("utf-8"))'

            elif method == "hex":
                enc = s.encode().hex()
                return f'(bytes.fromhex("{enc}").decode("utf-8"))'

            elif method == "zlib" and len(s) > 10:
                comp = zlib.compress(s.encode())
                b64 = base64.b64encode(comp).decode()
                imports_to_add.update({"import base64","import zlib"})
                return f'(__import__("zlib").decompress(__import__("base64").b64decode("{b64}")).decode("utf-8"))'

            elif method == "reverse":
                rev = s[::-1]
                b64 = base64.b64encode(rev.encode()).decode()
                imports_to_add.add("import base64")
                return f'(__import__("base64").b64decode("{b64}").decode("utf-8")[::-1])'

        except Exception:
            return None


    def obfuscate_strings(content: str) -> str:
        try:
            tokens = list(tokenize.generate_tokens(io.StringIO(content).readline))
            edits: List[Tuple[Tuple[int,int],Tuple[int,int],str]] = []
            for tok in tokens:
                if tok.type != tokenize.STRING: continue
                t = tok.string
                if t.startswith(('"""',"'''")): continue
                if t[:2].lower() in ('f"',"f'",'r"',"r'"): continue
                quote = t[0]
                if len(t)>=2 and t[-1]==quote:
                    inner = t[1:-1]
                else: continue
                if len(inner)<2: continue
                repl = encode_string_expr(inner)
                if repl: edits.append((tok.start,tok.end,repl))
            if not edits: return content
            lines = content.splitlines()
            for (sl,sc),(el,ec),rep in sorted(edits,key=lambda e:(e[0][0],e[0][1]),reverse=True):
                if sl==el and 1<=sl<=len(lines):
                    line = lines[sl-1]
                    lines[sl-1] = line[:sc]+rep+line[ec:]
            return ensure_imports("\n".join(lines))
        except Exception:
            return content

    # ------------- Number obfuscation -------------
    def obfuscate_numbers(content: str) -> str:
        def safe_int(tok:str)->Optional[int]:
            if any(c in tok.lower() for c in ('.','e','x','o','b','_')): return None
            try: return int(tok)
            except: return None
        def rep(n:int)->str:
            if abs(n)<=10: return str(n)
            m=abs(n)
            choice=random.choice([0,1,2,3])
            if choice==0:
                a=random.randint(1,m-1); b=m-a; expr=f"({a}+{b})"
            elif choice==1:
                k=random.randint(2,10); q,r=divmod(m,k); expr=f"({k}*{q}+{r})"
            elif choice==2:
                r=random.randint(1,100); expr=f"({m+r}-{r})"
            else: expr=f'int("{m}")'
            return f"-{expr}" if n<0 else expr
        try:
            tokens=list(tokenize.generate_tokens(io.StringIO(content).readline))
            lines=content.splitlines()
            edits=[]
            for tok in tokens:
                if tok.type==tokenize.NUMBER:
                    v=safe_int(tok.string)
                    if v is None: continue
                    edits.append((tok.start,tok.end,rep(v)))
            for (sl,sc),(el,ec),rp in sorted(edits,key=lambda e:(e[0][0],e[0][1]),reverse=True):
                if sl==el and 1<=sl<=len(lines):
                    line=lines[sl-1]
                    lines[sl-1]=line[:sc]+rp+line[ec:]
            return "\n".join(lines)
        except: return content

    # ------------- Name obfuscation (locals only) -------------
    def analyze_names(content:str):
        try:
            tree=ast.parse(content)
            imported:set[str]=set(); attrs:set[str]=set()
            class Scan(ast.NodeVisitor):
                def visit_Import(self,node):
                    for a in node.names: imported.add(a.name.split('.')[0])
                def visit_ImportFrom(self,node):
                    if node.module: imported.add(node.module.split('.')[0])
                    for a in node.names: imported.add(a.name)
                def visit_Attribute(self,node): attrs.add(node.attr); self.generic_visit(node)
            Scan().visit(tree)
            unsafe=builtin_names|imported|attrs|{'__name__','__main__','self','cls'}
            class Collect(ast.NodeVisitor):
                def __init__(self): self.local_stack=[]
                def visit_FunctionDef(self,node):
                    local=set()
                    for a in node.args.args:
                        if a.arg not in unsafe and len(a.arg)>1: local.add(a.arg)
                    self.local_stack.append(local)
                    self.generic_visit(node)
                    safe_to_rename.update(local); self.local_stack.pop()
                def visit_Assign(self,node):
                    if self.local_stack:
                        for t in node.targets:
                            if isinstance(t,ast.Name) and t.id not in unsafe: 
                                self.local_stack[-1].add(t.id)
                    self.generic_visit(node)
            Collect().visit(tree)
        except: safe_to_rename.clear()

    def rename_names(content:str)->str:
        if not safe_to_rename: return content
        mapping={}
        for n in sorted(safe_to_rename):
            mapping[n]=generate_random_name(prefix=n[:2])
        class Tx(ast.NodeTransformer):
            def visit_FunctionDef(self,node):
                for a in node.args.args:
                    if a.arg in mapping: a.arg=mapping[a.arg]
                self.generic_visit(node); return node
            def visit_Assign(self,node):
                for t in node.targets:
                    if isinstance(t,ast.Name) and t.id in mapping: t.id=mapping[t.id]
                self.generic_visit(node); return node
            def visit_Name(self,node):
                return ast.copy_location(ast.Name(id=mapping.get(node.id,node.id),ctx=node.ctx),node)
        new_tree=Tx().visit(ast.parse(content))
        return ast.unparse(new_tree)

    # ------------- Junk + Decoys + Fake imports -------------
    def add_cf_junk(content:str)->str:
        blocks=[]
        for i in range(2):
            v=generate_random_name(); fn=generate_random_name()
            blocks.append(f"{v}={random.randint(50,100)}\nif {v}>{random.randint(200,300)}:\n    def {fn}():\n        return {random.randint(1,9)}*{random.randint(10,99)}\n    {fn}()")
        lines=content.splitlines(); pos=0
        for i,l in enumerate(lines):
            if l.strip().startswith(("import ","from ")): pos=i+1
            elif l.strip() and not l.strip().startswith("#"): break
        lines.insert(pos,"\n".join(blocks)); return "\n".join(lines)

    def add_decoys(content:str)->str:
        fns=[f"def {generate_random_name()}(data):\n    return str(data)\n",
             f"def {generate_random_name()}(v,default=None):\n    try:return int(v)\n    except:return default\n",
             f"def {generate_random_name()}():\n    import sys\n    return sys.version_info>=(3,8)\n"]
        lines=content.splitlines(); pos=0
        for i,l in enumerate(lines):
            if l.strip().startswith(("import ","from ")): pos=i+1
            elif l.strip() and not l.strip().startswith("#"): break
        lines.insert(pos,"\n".join(fns)); return "\n".join(lines)

    def add_fake(content:str)->str:
        a1,a2,a3=generate_random_name(),generate_random_name(),generate_random_name()
        fake=[f"try:import numpy as {a1}\nexcept:{a1}=None",
              f"try:import pandas as {a2}\nexcept:{a2}=None",
              f"try:from matplotlib import pyplot as {a3}\nexcept:{a3}=None",
              f"class {generate_random_name()}:\n    def {generate_random_name()}(self,x=None):return x"]
        lines=content.splitlines(); pos=0
        for i,l in enumerate(lines):
            if l.strip().startswith(("import ","from ")): pos=i+1
            elif l.strip() and not l.strip().startswith("#"): break
        lines.insert(pos,"\n".join(fake)); return "\n".join(lines)

    # ------------- Exec wrapping -------------
    def wrap_exec(content:str,layers:int=3)->str:
        obf=content
        for _ in range(layers):
            encoded=base64.b64encode(obf.encode()).decode()
            obf=f"exec(__import__('base64').b64decode('{encoded}').decode())"
        code_hash=hashlib.sha256(obf.encode()).hexdigest()
        wrapper=f"""
import os,sys
sys.stdout = open(os.devnull, 'w')
sys.stderr = open(os.devnull, 'w')
import hashlib,sys,traceback,base64
code=\"\"\"{obf}\"\"\"
if hashlib.sha256(code.encode()).hexdigest()!=\"{code_hash}\":sys.exit(1)
try:exec(code)
except:sys.exit(1)
"""
        return textwrap.dedent(wrapper)

    # ------------- Pipeline -------------
    if not validate(code): return code
    analyze_names(code)
    code=obfuscate_strings(code)
    code=obfuscate_numbers(code)
    #code=rename_names(code)
    code=add_cf_junk(code)
    code=add_decoys(code)
    code=add_fake(code)
    if not validate(code): return code
    code=wrap_exec(code,3)
    return code
