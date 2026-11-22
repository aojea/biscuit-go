
# biscuit-go

biscuit-go is an implementation of [Biscuit](https://github.com/eclipse-biscuit/biscuit) in Go. It aims to be fully compatible with other existing implementations, so that tokens issued by, for example, the Rust version, could be validated by this library and vice versa.

## Documentation and specifications

- [biscuit website](https://www.biscuitsec.org) for documentation and examples
- [biscuit specification](https://github.com/eclipse-biscuit/biscuit)
- [biscuit-rust](https://github.com/eclipse-biscuit/biscuit-rust) for some more technical details.

## Specification compatibility

This library currently accepts datalog `v3.0` to `v3.3` blocks (block versions `3` to `6`, see
`MaxSchemaVersion`). Of datalog `v3.3`, `reject if`, the heterogeneous `==` and `!=`, `null`,
the lazy `&&` and `||`, the `.all()` / `.any()` closures, arrays, maps, `.type()`,
`extern::` function calls (registered with `WithExternFuncs`) and `.try_or()` are supported.

The [specification sample suite](./samples) runs in CI: samples using block versions above
`MaxSchemaVersion` are verified to be rejected and otherwise skipped, so they become active as
support for each version lands.

Tokens may be signed with Ed25519 or ECDSA on P-256 (`secp256r1`). `Biscuit.AuthorizerFrom`
takes a `RootKeyProvider` (`RootKey`, `RootKeysByID`, or your own function) for either key type;
`Biscuit.Authorizer` and `Biscuit.AuthorizerFor` still work with Ed25519 keys and are marked
deprecated. The `datalog.World` methods take the origin of each fact and the origins each rule
trusts, as in biscuit-rust.

### Differences from biscuit-rust

biscuit-rust is the reference implementation. The two implementations were compared with the same
tokens and the same authorizers. The known differences are:

- `reject if a or b` fails when one of its queries matches, as the specification says. biscuit-rust
  passes the check when one of its queries has no match.
- A block-level `trusting ...;` statement is kept in the block. biscuit-rust parses it and drops it.
- A block with arrays, maps or `.get()` is written as version `6`. biscuit-rust writes
  version `3`. The two are read.
- These tokens are refused here and accepted by biscuit-rust: a protobuf message with a required
  field that is missing, a version `3` block that uses datalog `v3.3` features, a P-256 key that is
  not compressed and that verifies a signature, a key with an algorithm that the schema does not
  define, and a block that declares one symbol two times.
- A rule that the authorizer itself adds, whose head has a variable that its body does not bind, is
  an error. In biscuit-rust it makes no fact.
- A rule and a query read the facts in the order in which they were added, and biscuit-rust reads
  them in sorted order. The result is the same. When more than one fact makes an expression fail,
  the execution error can be another one.
- A block with protobuf messages nested more than 100 levels deep is refused by the protobuf
  decoder of biscuit-rust: 48 closures, 49 arrays or 33 maps, one inside the other. The decoder of
  this library accepts 10000 levels, so such a token is read here.
- Regular expressions have the syntax of the Go `regexp` package, not of the Rust `regex` crate.
- A string is printed with `\"` and `\\`, so that the parser can read it again. biscuit-rust prints
  the string as it is.
- The two parsers do not accept exactly the same sources, see [the grammar](./parser/GRAMMAR.md).
  When the two accept a source, they make the same block. This parser refuses a source with more
  than 256 levels of nesting.
- The step limit and the deserialization limits of biscuit-rust 7 are not implemented.

## Usage

#### Create a biscuit
```go
rng := rand.Reader
publicRoot, privateRoot, _ := ed25519.GenerateKey(rng)

authority, err := parser.FromStringBlockWithParams(`
	right("/a/file1.txt", {read});
	right("/a/file1.txt", {write});
	right("/a/file2.txt", {read});
	right("/a/file3.txt", {write});
`, map[string]biscuit.Term{"read": biscuit.String("read"), "write": biscuit.String("write")})

if err != nil {
	panic(fmt.Errorf("failed to parse authority block: %v", err))
}

builder := biscuit.NewBuilder(privateRoot)
builder.AddBlock(authority)

b, err := builder.Build()
if err != nil {
	panic(fmt.Errorf("failed to build biscuit: %v", err))
}

token, err := b.Serialize()
if err != nil {
	panic(fmt.Errorf("failed to serialize biscuit: %v", err))
}

// token is now a []byte, ready to be shared
// The biscuit spec mandates the use of URL-safe base64 encoding for textual representation:
fmt.Println(base64.URLEncoding.EncodeToString(token))
```

#### Attenuate a biscuit

```go
b, err = biscuit.Unmarshal(token)
if err != nil {
    panic(fmt.Errorf("failed to deserialize biscuit: %v", err))
}

// Attenuate the biscuit by appending a new block to it
blockBuilder := b.CreateBlock()
block, err := parser.FromStringBlockWithParams(`
		check if resource($file), operation($permission), {{read}}.contains($permission);`,
	map[string]biscuit.Term{"read": biscuit.String("read")})
if err != nil {
	panic(fmt.Errorf("failed to parse block: %v", err))
}
blockBuilder.AddBlock(block)

attenuatedBiscuit, err := b.Append(rng, blockBuilder.Build())
if err != nil {
    panic(fmt.Errorf("failed to append: %v", err))
}
attenuatedToken, err := b.Serialize()
if err != nil {
    panic(fmt.Errorf("failed to serialize biscuit: %v", err))
}

// attenuatedToken is a []byte, representing an attenuated token
```

#### Append a third-party block

A third party signs a block for a token without seeing the token. Facts of that block are only
visible to rules that trust the third party's key.

```go
// Token holder: build the request for the third party.
request, err := b.ThirdPartyRequest()
if err != nil {
    panic(err)
}
requestBytes, _ := request.Serialize()

// Third party: sign a block for that request with its own key.
request, _ = biscuit.UnmarshalThirdPartyBlockRequest(requestBytes)
blockBuilder := biscuit.NewThirdPartyBlockBuilder()
blockBuilder.AddFact(biscuit.Fact{Predicate: biscuit.Predicate{Name: "group", IDs: []biscuit.Term{biscuit.String("admin")}}})
contents, err := request.CreateBlock(thirdPartyPrivateKey, blockBuilder)
if err != nil {
    panic(err)
}
contentsBytes, _ := contents.Serialize()

// Token holder: append the signed block.
contents, _ = biscuit.UnmarshalThirdPartyBlockContents(contentsBytes)
b, err = b.AppendThirdPartyBlock(nil, thirdPartyPublicKey, contents)
if err != nil {
    panic(err)
}

// A check trusting the third party's key sees group("admin"):
//   check if group("admin") trusting ed25519/<hex of thirdPartyPublicKey>
```

#### Verify a biscuit

```go
b, err := biscuit.Unmarshal(token)
if err != nil {
    panic(fmt.Errorf("failed to deserialize token: %v", err))
}

authorizer, err := b.AuthorizerFrom(biscuit.RootKey(publicRoot))
if err != nil {
    panic(fmt.Errorf("failed to verify token and create authorizer: %v", err))
}

authorizerContents, err := parser.FromStringAuthorizerWithParams(`
	resource({res});
	operation({op});
	allow if right({res}, {op});
	`, map[string]biscuit.Term{"res": biscuit.String("/a/file1.txt"), "op": biscuit.String("read")})
if err != nil {
	panic(fmt.Errorf("failed to parse authorizer: %v", err))
}
authorizer.AddAuthorizer(authorizerContents)

if err := authorizer.Authorize(); err != nil {
    fmt.Printf("failed authorizing token: %v\n", err)
} else {
    fmt.Println("success authorizing token")
}
```

### Using biscuit-go grammar

biscuit-go provides a datalog parser, allowing to input datalog elements as plain strings, along with support for parameter substitution. 

See [GRAMMAR reference](./parser/GRAMMAR.md) for the complete syntax.

The parsers supports parsing whole blocks (containing several facts, rules and checks), whole authorizers (containing several facts, rules, checks and policies), as well as individual facts, rules, checks and policies. Parsing and adding elements individually is especially useful when doing so from inside a loop. 

The `parser` module provides convenient helpers for parsing a string into datalog elements (`FromStringFact`, `FromStringRule`, `FromStringCheck`, `FromStringPolicy`, `FromStringBlock`, `FromStringAuthorizer`, for static datalog snippets, and their counterparts allowing parameter substitution: `FromStringFactWithParams`, `FromStringRuleWithParams`, `FromStringCheckWithParams`, `FromStringPolicyWithParams`, `FromStringBlockWithParams`, `FromStringAuthorizerWithParams`).

#### Panic on parsing errors

In most cases, `FromString*` functions will let you handle errors. If you do not wish to handle errors and instead crash on errors (for instance in one-off scripts), it can be done by first creating a parser instance, and using the `panic`-y functions:

```go
p := parser.New()
b := biscuit.NewBuilder(privateRoot)

b.AddBlock(p.Must().Block(`
	right("/a/file1.txt", {read});
	right("/a/file1.txt", {write});
	right("/a/file2.txt", {read});
	right("/a/file3.txt", {write});
`, map[string]biscuit.Term{"read": biscuit.String("read"), "write": biscuit.String("write")}))

b.AddFact(p.Must().Fact(`resource({res})`, map[string]biscuit.Term{"res": biscuit.String("/a/file1.txt")}))
b.AddRule(p.Must().Rule(`
    can_read($file) 
        <- resource($file)
        $file.starts_with("/a/")
`, nil))
```

Do note that these helpers take two arguments: a datalog snippet and a parameters map. If the datalog snippet does not contain parameters, `nil` can be passed as the second argument.

## Examples

- [example_test.go](./example_test.go) for a simple use case
- [experiments folder](./experiments) for more advanced or specific use cases examples.

## License

Licensed under [Apache License, Version 2.0](./LICENSE).
