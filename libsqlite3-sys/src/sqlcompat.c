/*
** SmoothCSV JS-compat helper, included once from sqlcipher/sqlite3.c via
** #include "../src/sqlcompat.c" just before sqlite3VdbeExec.
**
** Implements ECMA-262 Abstract Relational Comparison + Abstract Equality
** semantics for the SCALAR comparison opcodes (OP_Eq / OP_Ne / OP_Lt /
** OP_Gt / OP_Le / OP_Ge) of the VDBE engine. The dispatch site sits
** before the MEM_Int fast path inside the shared opcode handler and
** falls through to legacy SQLite behavior for cases this helper does
** not handle (SQLITE_NULLEQ, MEM_Null, MEM_Blob, etc.).
**
** Design constraints (see issues/open/191-plan.md §Step B for the full
** rationale):
**
**   1. Non-destructive read. We MUST NOT call sqlite3VdbeChangeEncoding
**      on input Mems — the trailing `pIn1->flags = flags1` restore in
**      the opcode handler would leave the Mem in an inconsistent state
**      otherwise. All string/number coercion routes input through
**      ScCpReader, which streams codepoints out of pMem->z bounded by
**      pMem->n, dispatching on pMem->enc.
**
**   2. ECMA-262 string-to-number semantics. scJsToNumber implements
**      StringToNumber per the ECMA spec: whitespace (WhiteSpace ∪
**      LineTerminator) trim, "Infinity" / "+Infinity" / "-Infinity",
**      hex (0x…), octal (0o…), binary (0b…) literals (no sign, non-
**      empty digits), and decimal literals via sqlite3AtoF. Anything
**      else, including non-ASCII codepoints outside the whitespace
**      allowlist, returns NaN.
**
**   3. NaN branch. ECMA Abstract Relational Comparison + Abstract
**      Equality yields:
**        - any relational (<, >, <=, >=) on NaN → false
**        - == on NaN → false
**        - != on NaN → true
**      The dispatch sets res2 directly and jumps past the legacy
**      res→res2 mapping to avoid the legacy `iCompare = res` overwrite
**      of our explicit iCompare = 1.
**
**   4. UTF-16 code-unit lex compare. scStrCmpJsLike walks both
**      operands as code-unit streams (one for BMP, two for the
**      supplementary plane via surrogate pair). This matches JS
**      String comparison exactly, including the surrogate-vs-BMP
**      ordering quirk for codepoints ≥ U+10000.
*/

#ifndef SC_JSCOMPAT_C_INCLUDED
#define SC_JSCOMPAT_C_INCLUDED

#include <math.h>   /* for INFINITY */

/* Kind tags for the dispatch in the opcode handler.
**
** SC_K_NUM: any of MEM_Int / MEM_Real / MEM_IntReal set. The combined
**     (MEM_Int | MEM_Str) case (stringified-numeric cache) still
**     classifies as NUM — the cached numeric value is authoritative.
** SC_K_STR: pure MEM_Str without numeric flags and without MEM_Blob.
** SC_K_BLOB: MEM_Blob without numeric flags. The spec does not cover
**     blob comparison; the dispatch falls through to legacy.
*/
#define SC_K_STR  1
#define SC_K_NUM  2
#define SC_K_BLOB 3

/* Classify a Mem operand. MEM_Null is filtered out upstream by the
** dispatch site so we can assume the operand is non-null here. */
static int scJsKind(const Mem *pMem){
  u16 f = pMem->flags;
  if( f & (MEM_Int | MEM_Real | MEM_IntReal) ) return SC_K_NUM;
  if( f & MEM_Blob ) return SC_K_BLOB;
  /* MEM_Str (or no flag, which should not happen for non-null) */
  return SC_K_STR;
}

/* -------------------------------------------------------------------------
** ScCpReader — non-destructive codepoint stream over pMem->z.
**
** Dispatches on pMem->enc:
**   SQLITE_UTF8     — walks UTF-8 bytes, decoding to codepoints.
**   SQLITE_UTF16LE  — reads 16-bit code units little-endian.
**   SQLITE_UTF16BE  — reads 16-bit code units big-endian.
**
** Length-bounded (pMem->n), not NUL-terminated: SmoothCSV cells can
** legitimately contain embedded NUL bytes.
*/
typedef struct ScCpReader {
  const unsigned char *p;
  const unsigned char *end;
  unsigned char enc; /* SQLITE_UTF8 / SQLITE_UTF16LE / SQLITE_UTF16BE */
} ScCpReader;

static void scReaderInit(ScCpReader *r, const Mem *pMem){
  r->p = (const unsigned char *)pMem->z;
  r->end = r->p + (pMem->n > 0 ? pMem->n : 0);
  r->enc = pMem->enc;
}

/* Read the next codepoint into *outCp.
** Returns 1 on success, 0 at EOF. Invalid encoding sequences (lone
** trailing surrogate, truncated UTF-8) decode to U+FFFD to match JS
** String iteration behavior, which never throws on ill-formed input.
**
** TODO(step-b-subagent): implement UTF-8 + UTF-16LE/BE decoders here.
** Until then this returns EOF immediately so the surrounding
** dispatch produces well-defined "empty string" semantics.
*/
static int scReadCp(ScCpReader *r, u32 *outCp){
  (void)r; (void)outCp;
  return 0;
}

/* -------------------------------------------------------------------------
** scStrCmpJsLike — JS String relational comparison.
**
** Walks both readers in lockstep, emitting UTF-16 code units (one per
** BMP codepoint, two per supplementary). Compares code units pairwise
** until one stream ends. Returns -1 / 0 / +1 matching the caller's
** convention (res < 0 ⇒ pB < pA, etc., mirroring sqlite3MemCompare).
**
** Argument order mirrors the call in sqlite3.c:
**   res = scStrCmpJsLike(pIn3, pIn1);
** so pA == pIn3 (left operand of the SQL expression) and
**    pB == pIn1 (right operand).
**
** TODO(step-b-subagent): implement code-unit emission, surrogate pair
** decoding from each reader's codepoint, and BMP/supplementary
** ordering. Stub returns 0 (equal) so legacy fallthrough semantics
** are not silently bypassed.
*/
static int scStrCmpJsLike(const Mem *pA, const Mem *pB){
  (void)pA; (void)pB;
  return 0;
}

/* -------------------------------------------------------------------------
** scJsToNumber — ECMA-262 ToNumber for VDBE Mem operands.
**
** On success, writes the coerced double to *out and returns 1.
** On NaN (parse failure, non-allowlisted non-ASCII codepoint, OOM
** during scratch-buffer growth, etc.), returns 0; *out is unspecified.
**
** Numeric Mems (MEM_Int / MEM_Real / MEM_IntReal) coerce directly:
**   - MEM_Int is cast to double, deliberately losing precision beyond
**     2^53 to match JS Number semantics.
**   - MEM_Real returns its stored value.
**
** String Mems run through the StringToNumber pipeline:
**   1. Trim leading + trailing whitespace (ECMA WhiteSpace ∪
**      LineTerminator).
**   2. Empty / all-whitespace → 0.
**   3. "Infinity" / "+Infinity" / "-Infinity" literals → ±INFINITY.
**   4. Non-decimal prefixes 0x… / 0o… / 0b… (no sign, non-empty
**      digits) → parsed as hex / octal / binary; over-long inputs
**      may saturate to INFINITY.
**   5. Otherwise, route to sqlite3AtoF for decimal parsing (sign,
**      fractional, exponent).
**   6. Any other shape → NaN (return 0).
**
** Non-ASCII codepoints anywhere except in the whitespace allowlist
** trigger immediate NaN.
**
** TODO(step-b-subagent): full implementation. Scaffold currently
** handles only the direct numeric Mem cases; string Mems fall through
** to NaN. This is intentionally noisy so unimplemented paths surface
** in the spec test.
*/
static int scJsToNumber(const Mem *pMem, double *out){
  u16 f = pMem->flags;
  if( f & MEM_Int ){
    *out = (double)pMem->u.i;
    return 1;
  }
  if( f & MEM_IntReal ){
    *out = (double)pMem->u.i;
    return 1;
  }
  if( f & MEM_Real ){
    *out = pMem->u.r;
    return 1;
  }
  /* MEM_Str / MEM_Blob / other: subagent implementation. */
  (void)out;
  return 0;
}

#endif /* SC_JSCOMPAT_C_INCLUDED */
