# go-dnsdb

`dnsdb` is an implementation of the [DNSDB HTTP API](https://docs.dnsdb.info/) for the [Go](http://www.golang.org/)
programming language.

Please see https://www.farsightsecurity.com/solutions/dnsdb/ for more information.

## Requirements

 * Golang 1.11 or greater
 * Farsight DNSDB API key

## Installation

`go get -t github.com/dnsdb/go-dnsdb`

## Usage

`dnsdb` supports both the DNSDB API v1 and v2 protocols using the [`Client`](pkg/dnsdb/client.go) interface.
Parameters are set for immutable Query objects using `With*` functions and the query is executed by calling the `Query.Do(context.Context)` function.
Both clients support streaming results that are delivered asynchronously via channels.
Please see the [API documentation](pkg/dnsdb) for more details.

### Interfaces

The DNSDB API is implemented using five different interfaces. This allows for the `dnsdb.Client` interface to be used
by implementations of passive DNS databases that output records formatted with the
[Passive DNS Common Output Format](https://tools.ietf.org/id/draft-dulaunoy-dnsop-passive-dns-cof-03.html).

* The [Flexible Search Client](https://godoc.org/github.com/dnsdb/go-dnsdb/pkg/dnsdb/flex#Client) interface provides access to the v2 flexible search API functions.
* The [Client](https://godoc.org/github.com/dnsdb/go-dnsdb/pkg/dnsdb#Client) interface provides access to the lookup API functions.
* The [SummarizeClient](https://godoc.org/github.com/dnsdb/go-dnsdb/pkg/dnsdb#SummarizeClient) interface provides access to the summarize API functions.
* The [RateLimitClient](https://godoc.org/github.com/dnsdb/go-dnsdb/pkg/dnsdb#RateLimitClient) interface provides access to the rate limit API functions.
* The [PingClient](https://godoc.org/github.com/dnsdb/go-dnsdb/pkg/dnsdb#PingClient) interface provides access to the APIv2 ping function.


## Example

```go
package main

import (   
    "context"
    "errors"
    "log"

    "github.com/dnsdb/go-dnsdb/pkg/dnsdb"
    "github.com/dnsdb/go-dnsdb/pkg/dnsdb/v2"
)

func main() {
    c := &v2.Client{
        Apikey: "<your api key here>",
    }

    ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
    defer cancel()

    res := c.LookupRRSet("farsightsecurity.com").WithRRType("A").Do(ctx)
    if err != nil {
        log.Fatalf("lookup failed: %s", err)
    }
    defer res.Close()

    for record := range res.Ch() {
        // do something with record
    }
    if res.Err() != nil {
        if !errors.Is(err, dnsdb.ErrResultLimitExceeded) {
            log.Fatalf("lookup failed: %s", res.Err())
        }
    }
}
```

## How To

### Combine Interfaces

The DNSDB API is split up into multiple interfaces to make development and testing easier for implementors. If you
prefer to combine these applications in your application you can define an interface that is composed of all of the
interfaces that you wish to use.

```go
interface DnsdbV2Client {
    dnsdb.Client
    dnsdb.SummarizeClient
    dnsdb.RateLimitClient
    dnsdb.PingClient
}
```

Alternately, you can use type assertions to see if the client implementation supports the functionality that you want to use.

```go
func ping(ctx context.Context, c dnsdb.Client) error {
    if p, ok := c.(dnsdb.PingClient); ok {
        return p.Ping.Do(ctx)
    }
    return nil
}
```
