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
** surrogate, truncated UTF-8 / UTF-16) decode to U+FFFD to match JS
** String iteration behavior, which never throws on ill-formed input.
*/
static int scReadCp(ScCpReader *r, u32 *outCp){
  if( r->p >= r->end ) return 0;
  if( r->enc == SQLITE_UTF8 ){
    u32 c;
    int n = sqlite3Utf8ReadLimited(r->p, (int)(r->end - r->p), &c);
    r->p += n;
    /* Reject lone surrogates and non-characters per sqlite3Utf8Read's
    ** standard sanitization, mirroring JS behavior of substituting
    ** U+FFFD on ill-formed sequences. */
    if( c < 0x80 ){
      /* Fine. */
    }else if( (c & 0xFFFFF800) == 0xD800
           || (c & 0xFFFFFFFE) == 0xFFFE
           || c > 0x10FFFF ){
      c = 0xFFFD;
    }
    *outCp = c;
    return 1;
  }else{
    /* UTF-16LE / UTF-16BE. */
    int swap = (r->enc == SQLITE_UTF16BE);
    u32 u;
    if( r->end - r->p < 2 ){
      /* Truncated unit: substitute replacement and advance to end. */
      r->p = r->end;
      *outCp = 0xFFFD;
      return 1;
    }
    u = swap ? ((u32)r->p[0] << 8) | r->p[1]
             : ((u32)r->p[1] << 8) | r->p[0];
    r->p += 2;
    if( u >= 0xD800 && u <= 0xDBFF ){
      /* High surrogate — try to read a paired low surrogate. */
      if( r->end - r->p >= 2 ){
        u32 v = swap ? ((u32)r->p[0] << 8) | r->p[1]
                     : ((u32)r->p[1] << 8) | r->p[0];
        if( v >= 0xDC00 && v <= 0xDFFF ){
          r->p += 2;
          *outCp = 0x10000 + (((u - 0xD800) << 10) | (v - 0xDC00));
          return 1;
        }
      }
      *outCp = 0xFFFD;  /* Orphan high surrogate. */
      return 1;
    }
    if( u >= 0xDC00 && u <= 0xDFFF ){
      *outCp = 0xFFFD;  /* Bare low surrogate. */
      return 1;
    }
    *outCp = u;
    return 1;
  }
}

/* True if `cp` is in the ECMA-262 WhiteSpace ∪ LineTerminator allowlist.
** This is the trim allowlist for StringToNumber. */
static int scIsEcmaWhitespace(u32 cp){
  /* ASCII fast path. */
  if( cp <= 0x20 ){
    return cp == 0x09  /* TAB */
        || cp == 0x0A  /* LF */
        || cp == 0x0B  /* VT */
        || cp == 0x0C  /* FF */
        || cp == 0x0D  /* CR */
        || cp == 0x20; /* SP */
  }
  switch( cp ){
    case 0x00A0:  /* NBSP */
    case 0x1680:  /* Ogham space mark */
    case 0x2000: case 0x2001: case 0x2002: case 0x2003:
    case 0x2004: case 0x2005: case 0x2006: case 0x2007:
    case 0x2008: case 0x2009: case 0x200A:  /* en/em/etc. spaces */
    case 0x2028:  /* Line separator */
    case 0x2029:  /* Paragraph separator */
    case 0x202F:  /* Narrow NBSP */
    case 0x205F:  /* Medium mathematical space */
    case 0x3000:  /* Ideographic space */
    case 0xFEFF:  /* BOM / ZWNBSP */
      return 1;
    default:
      return 0;
  }
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
*/

/* Next UTF-16 code unit from a stream of codepoints.
**
** A supplementary codepoint (>= U+10000) emits two code units (high
** then low surrogate) over two calls. `pPending` holds the low
** surrogate between the two calls; it is zero when no codepoint is
** mid-emission. Returns 1 on success, 0 at EOF.
*/
static int scNextUtf16Unit(ScCpReader *r, u32 *pPending, u32 *outUnit){
  u32 cp;
  if( *pPending ){
    *outUnit = *pPending;
    *pPending = 0;
    return 1;
  }
  if( !scReadCp(r, &cp) ) return 0;
  if( cp >= 0x10000 ){
    /* Supplementary plane: emit high surrogate now, low next call. */
    u32 c = cp - 0x10000;
    *outUnit = 0xD800 | (c >> 10);
    *pPending = 0xDC00 | (c & 0x3FF);
  }else{
    *outUnit = cp;
  }
  return 1;
}

static int scStrCmpJsLike(const Mem *pA, const Mem *pB){
  ScCpReader ra, rb;
  u32 penA = 0, penB = 0;
  scReaderInit(&ra, pA);
  scReaderInit(&rb, pB);
  for(;;){
    u32 ua = 0, ub = 0;
    int hasA = scNextUtf16Unit(&ra, &penA, &ua);
    int hasB = scNextUtf16Unit(&rb, &penB, &ub);
    if( !hasA && !hasB ) return 0;
    if( !hasA ) return -1;  /* A is a prefix of B. */
    if( !hasB ) return +1;  /* B is a prefix of A. */
    if( ua < ub ) return -1;
    if( ua > ub ) return +1;
  }
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
*/

/* Parse a non-decimal-prefix literal: hex (0x/0X), octal (0o/0O),
** binary (0b/0B). Caller has already verified the prefix; `z` points
** at the first digit, `n` is the count of digits left. Returns 1 on
** success (writing to *out), 0 on NaN.
**
** Empty digits → NaN. Invalid digit anywhere → NaN.
** Over-long inputs saturate to INFINITY (deliberate; JS Number does the
** same since the value exceeds finite double range).
*/
static int scParseRadixDigits(
  const char *z, int n, int radix, double *out
){
  double v = 0.0;
  int i;
  if( n <= 0 ) return 0;
  for(i=0; i<n; i++){
    int d;
    char c = z[i];
    if( c >= '0' && c <= '9' ){
      d = c - '0';
    }else if( radix == 16 && c >= 'a' && c <= 'f' ){
      d = 10 + (c - 'a');
    }else if( radix == 16 && c >= 'A' && c <= 'F' ){
      d = 10 + (c - 'A');
    }else{
      return 0;
    }
    if( d >= radix ) return 0;
    v = v * (double)radix + (double)d;
  }
  *out = v;
  return 1;
}

/* True if c (ASCII) is a digit for sqlite3AtoF's decimal grammar use. */
#define SC_IS_DIGIT(c)  ((c) >= '0' && (c) <= '9')

/* Validate that `z[0..n)` is a strict ECMA-262 StrDecimalLiteral.
**
** sqlite3AtoF is permissive: returns -1 on partial parses like "5e".
** ECMA-262 demands a complete parse. This function inspects the ASCII
** body produced by scJsToNumber's trim/normalize step and returns 1
** only if it conforms to:
**
**     StrDecimalLiteral ::
**       [+-]? StrUnsignedDecimalLiteral
**     StrUnsignedDecimalLiteral ::
**       DecimalDigits . DecimalDigits? ExponentPart?
**     | . DecimalDigits ExponentPart?
**     | DecimalDigits ExponentPart?
**     ExponentPart ::
**       e[+-]? DecimalDigits
**
** "Infinity" with optional sign is handled by the caller.
*/
static int scIsStrictStrDecimalLiteral(const char *z, int n){
  int i = 0;
  int hasIntDigits = 0;
  int hasFracDigits = 0;
  if( n == 0 ) return 0;
  if( z[i] == '+' || z[i] == '-' ){ i++; }
  while( i < n && SC_IS_DIGIT(z[i]) ){ i++; hasIntDigits = 1; }
  if( i < n && z[i] == '.' ){
    i++;
    while( i < n && SC_IS_DIGIT(z[i]) ){ i++; hasFracDigits = 1; }
  }
  if( !hasIntDigits && !hasFracDigits ) return 0;
  if( i < n && (z[i] == 'e' || z[i] == 'E') ){
    i++;
    if( i < n && (z[i] == '+' || z[i] == '-') ){ i++; }
    if( i >= n || !SC_IS_DIGIT(z[i]) ) return 0;
    while( i < n && SC_IS_DIGIT(z[i]) ){ i++; }
  }
  return i == n;
}

/* Compare an ASCII tail-trimmed scratch buffer to an ASCII literal
** like "Infinity". Returns 1 on byte-exact match. */
static int scAsciiEquals(const char *z, int n, const char *lit){
  int i;
  for(i=0; i<n; i++){
    if( lit[i] == 0 ) return 0;
    if( z[i] != lit[i] ) return 0;
  }
  return lit[n] == 0;
}

/* Collect the body of pMem's string into an ASCII scratch buffer,
** trimming ECMA WhiteSpace ∪ LineTerminator at both ends. Returns 1
** on success (writing the body to `*pBuf` / `*pLen`) and 0 if the
** value is NaN per the spec — i.e. any non-ASCII non-whitespace
** codepoint, or OOM while growing the scratch buffer.
**
** `stack` is a caller-provided fixed-size scratch buffer; if the
** body exceeds `stackCap`, the function grows on the heap with
** `sqlite3_malloc`. `*pAlloced` is set when the heap path is taken so
** the caller knows to call `sqlite3_free`.
**
** Trim semantics: a "trim head" state skips leading whitespace
** entirely. Once any non-whitespace codepoint is seen, all subsequent
** codepoints are appended to the buffer; the running `bodyEnd`
** records the buffer length after the most recent ASCII-non-whitespace
** codepoint, so the final length naturally excludes trailing
** whitespace without a second pass. Non-ASCII whitespace codepoints
** are NEVER appended (they have no role in the ECMA-262 decimal
** grammar) — they only count as potential trailing whitespace.
*/
static int scCollectAsciiBody(
  const Mem *pMem,
  char *stack,
  int stackCap,
  char **pBuf,
  int *pLen,
  int *pAlloced
){
  ScCpReader r;
  char *buf = stack;
  int cap = stackCap;
  int len = 0;       /* current buffer length */
  int bodyEnd = 0;   /* len after the last ASCII-non-whitespace byte */
  int alloced = 0;
  int trimmingLead = 1;
  u32 cp;
  scReaderInit(&r, pMem);
  while( scReadCp(&r, &cp) ){
    int isWs = scIsEcmaWhitespace(cp);
    if( trimmingLead ){
      if( isWs ) continue;
      trimmingLead = 0;
    }
    if( cp >= 0x80 ){
      /* Non-ASCII whitespace contributes to trim only; non-ASCII
      ** non-whitespace is invalid in the ECMA decimal grammar. */
      if( isWs ) continue;
      if( alloced ) sqlite3_free(buf);
      return 0;
    }
    if( len + 1 > cap ){
      int newCap = cap * 2;
      char *next;
      if( newCap < len + 1 ) newCap = len + 1;
      next = (char *)sqlite3_malloc(newCap);
      if( next == 0 ){
        if( alloced ) sqlite3_free(buf);
        return 0;
      }
      if( len > 0 ) memcpy(next, buf, (size_t)len);
      if( alloced ) sqlite3_free(buf);
      buf = next;
      cap = newCap;
      alloced = 1;
    }
    buf[len++] = (char)cp;
    if( !isWs ) bodyEnd = len;
  }
  *pBuf = buf;
  *pLen = bodyEnd;
  *pAlloced = alloced;
  return 1;
}

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
  if( (f & MEM_Str) == 0 ){
    return 0;
  }
  {
    char stack[128];
    char *buf = 0;
    int len = 0;
    int alloced = 0;
    int ok;
    double value = 0.0;
    int success = 0;

    if( !scCollectAsciiBody(pMem, stack, sizeof(stack),
                            &buf, &len, &alloced) ){
      return 0;
    }

    if( len == 0 ){
      value = 0.0;
      success = 1;
      goto done;
    }

    /* Infinity literals. */
    if( scAsciiEquals(buf, len, "Infinity")
     || scAsciiEquals(buf, len, "+Infinity") ){
      value = (double)INFINITY;
      success = 1;
      goto done;
    }
    if( scAsciiEquals(buf, len, "-Infinity") ){
      value = -(double)INFINITY;
      success = 1;
      goto done;
    }

    /* Non-decimal prefix literals (no sign permitted). */
    if( len >= 2 && buf[0] == '0' ){
      int radix = 0;
      char p = buf[1];
      if( p == 'x' || p == 'X' )      radix = 16;
      else if( p == 'o' || p == 'O' ) radix = 8;
      else if( p == 'b' || p == 'B' ) radix = 2;
      if( radix > 0 ){
        if( scParseRadixDigits(buf + 2, len - 2, radix, &value) ){
          success = 1;
        }
        /* Whether parse succeeded or not, the 0x/0o/0b prefix is
        ** exclusive: do not fall through to decimal parsing. */
        goto done;
      }
    }

    /* Strict decimal validation, then sqlite3AtoF for the value. */
    if( !scIsStrictStrDecimalLiteral(buf, len) ){
      goto done;
    }
    ok = sqlite3AtoF(buf, &value, len, SQLITE_UTF8);
    if( ok > 0 ){
      success = 1;
    }
    /* ok == -1 means partial parse; treat as NaN (we already
    ** rejected most partial inputs via the strict validator). */

  done:
    if( alloced ) sqlite3_free(buf);
    if( success ){
      *out = value;
      return 1;
    }
    return 0;
  }
}

#endif /* SC_JSCOMPAT_C_INCLUDED */
