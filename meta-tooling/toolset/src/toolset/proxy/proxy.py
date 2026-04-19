from __future__ import annotations

import base64
from typing import Annotated, Any

from gql import Client, gql
from gql.transport.requests import RequestsHTTPTransport

from core import namespace, tool, toolset


namespace()


@toolset()
class Proxy:
    def __init__(self, url: str | None, token: str | None):
        self.url = url
        self.token = token
        self._client: Client | None = None

    def _ensure_client(self) -> Client:
        if not self.url or not self.token:
            raise RuntimeError("CAIDO is not configured. Set CAIDO_PORT and CAIDO_TOKEN to use proxy tools.")
        if self._client is None:
            transport = RequestsHTTPTransport(
                url=self.url,
                headers={"Authorization": f"Bearer {self.token}"},
            )
            self._client = Client(transport=transport)
        return self._client

    @staticmethod
    def _config_error(exc: Exception) -> dict[str, Any]:
        return {"error": str(exc)}

    @tool()
    def list_traffic(
        self,
        limit: int = 5,
        offset: int = 0,
        filter: Annotated[
            str,
            """Caido HTTPQL statement, such as ' req.host.like:"%.example.com" and req.method.like:"POST" ' """,
        ] = None,
    ) -> dict:
        try:
            query = gql(
                """
                query($offset: Int, $limit: Int, $filter: HTTPQL) {
                  interceptEntriesByOffset(
                    limit: $limit
                    offset: $offset
                    filter: $filter
                    order: {by: REQ_CREATED_AT, ordering: DESC}
                  ) {
                    count {
                      value
                    }
                    nodes {
                      request {
                        id
                        createdAt
                        host
                        port
                        method
                        path
                        query
                        length
                        response {
                          length
                          roundtripTime
                          statusCode
                        }
                      }
                    }
                  }
                }
                """
            )
            effective_filter = f"{filter} and preset:no-images and preset:no-styling" if filter else "preset:no-images and preset:no-styling"
            client = self._ensure_client()
            result = client.execute(
                query,
                variable_values={"limit": limit, "offset": offset, "filter": effective_filter},
            )
            return result["interceptEntriesByOffset"]
        except Exception as exc:
            return self._config_error(exc)

    @tool()
    def view_traffic(
        self,
        id: int,
        b64encode: Annotated[
            bool,
            "whether the returned traffic needs to be base64 encoded. Generally, not required, so you can view the results directly",
        ] = False,
    ) -> dict:
        try:
            query = gql(
                """
                query ($id: ID!) {
                  request(id: $id) {
                    id
                    isTls
                    host
                    port
                    raw
                    response {
                        roundtripTime
                        raw
                    }
                  }
                }
                """
            )
            client = self._ensure_client()
            result = client.execute(query, variable_values={"id": str(id)})
            if not b64encode and result["request"] and "raw" in result["request"]:
                result["request"]["raw"] = base64.b64decode(result["request"]["raw"]).decode("utf-8", errors="replace")
                if result["request"]["response"] and "raw" in result["request"]["response"]:
                    result["request"]["response"]["raw"] = base64.b64decode(
                        result["request"]["response"]["raw"]
                    ).decode("utf-8", errors="replace")
            return result
        except Exception as exc:
            return self._config_error(exc)


if __name__ == "__main__":
    from . import proxy

    proxy.list_traffic()
