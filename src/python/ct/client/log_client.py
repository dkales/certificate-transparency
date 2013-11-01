"""RFC 6962 client API."""
import base64

from ct.proto import client_pb2
import gflags
import requests

FLAGS = gflags.FLAGS

gflags.DEFINE_integer("entry_fetch_batch_size", 1000, "Maximum number of "
                      "entries to attempt to fetch in one request")


class Error(Exception):
    pass


class ClientError(Error):
    pass


class HTTPError(Error):
    """Connection failed, or returned an error."""
    pass


class HTTPClientError(HTTPError):
    """HTTP 4xx."""
    pass


class HTTPServerError(HTTPError):
    """HTTP 5xx."""
    pass


class InvalidRequestError(Error):
    """Request does not comply with the CT protocol."""
    pass


class InvalidResponseError(Error):
    """Response does not comply with the CT protocol."""
    pass


# requests.models.Response is not easily instantiable locally, so as a
# workaround, encapsulate the entire http logic in the Requester class which we
# can control/mock out to test response handling.
class Requester(object):
    """HTTPS requests."""

    def __init__(self, uri):
        self.__uri = uri

    def __repr__(self):
        return "%r(%r)" % (self.__class__.__name__, self.__uri)

    def __str__(self):
        return "%r(%r)" % (self.__class__.__name__, self.__uri)

    @property
    def uri(self):
        return self.__uri

    def get_json_response(self, path, params=None):
        """Get the json contents of a request response."""
        url = "https://" + self.__uri + "/" + path
        try:
            response = requests.get(url, params=params, timeout=60)
        except requests.exceptions.RequestException as e:
            raise HTTPError("Connection to %s failed: %s" % (url, e))
        if not response.ok:
            error_msg = ("%s returned http_error %d: %s" %
                         (url, response.status_code,
                          response.text.encode("ascii", "ignore")))
            if 400 <= response.status_code < 500:
                raise HTTPClientError(error_msg)
            elif 500 <= response.status_code < 600:
                raise HTTPServerError(error_msg)
            else:
                raise HTTPError(error_msg)
        try:
            return response.json()
        # This can raise a variety of undocumented exceptions...
        except Exception as e:
            raise InvalidResponseError("Response %s from %s is not valid JSON: "
                                       "%s" % (response, url, e))


class LogClient(object):
    """HTTP client for talking to a CT log."""

    _GET_STH_PATH = "ct/v1/get-sth"
    _GET_ENTRIES_PATH = "ct/v1/get-entries"
    _GET_STH_CONSISTENCY_PATH = "ct/v1/get-sth-consistency"
    _GET_PROOF_BY_HASH_PATH = "ct/v1/get-proof-by-hash"
    _GET_ROOTS_PATH = "ct/v1/get-roots"
    _GET_ENTRY_AND_PROOF_PATH = "ct/v1/get-entry-and-proof"

    def __init__(self, requester):
        self.__req = requester

    def __repr__(self):
        return "%r(%r)" % (self.__class__.__name__, self.__req)

    def __str__(self):
        return "%s(%s)" % (self.__class__.__name__, self.__req.uri)

    @property
    def servername(self):
        return self.__req.uri

    def get_sth(self):
        """Get the current Signed Tree Head.

        Returns:
            a ct.proto.client_pb2.SthResponse proto.

        Raises:
            HTTPError, HTTPClientError, HTTPServerError: connection failed.
                For logs that honour HTTP status codes, HTTPClientError (a 4xx)
                should never happen.
            InvalidResponseError: server response is invalid for the given
                                  request.
        """
        sth = self.__req.get_json_response(self._GET_STH_PATH)
        sth_response = client_pb2.SthResponse()
        try:
            sth_response.timestamp = sth["timestamp"]
            sth_response.tree_size = sth["tree_size"]
            sth_response.sha256_root_hash = base64.b64decode(sth[
                "sha256_root_hash"])
            sth_response.tree_head_signature = base64.b64decode(sth[
                "tree_head_signature"])
        # TypeError for base64 decoding, TypeError/ValueError for invalid
        # JSON field types, KeyError for missing JSON fields.
        except (TypeError, ValueError, KeyError) as e:
            raise InvalidResponseError("%s returned an invalid STH %s\n%s" %
                                       (self.__req.uri, sth, e))
        return sth_response

    def __json_entry_to_response(self, json_entry):
        """Convert a json array element to an EntryResponse."""
        entry_response = client_pb2.EntryResponse()
        try:
            entry_response.leaf_input = base64.b64decode(
                json_entry["leaf_input"])
            entry_response.extra_data = base64.b64decode(
                json_entry["extra_data"])
        except (TypeError, ValueError, KeyError) as e:
            raise InvalidResponseError(
                "%s returned invalid data: expected a log entry, got %s"
                "\n%s" % (self.__req.uri, json_entry, e))
        return entry_response

    def __validated_entry_response(self, start, end, response):
        """Verify the get-entries response format and size.

        Args:
            start: requested start parameter.
            end:  requested end parameter.
            response: response.

        Returns:
            an array of entries.

        Raises:
            InvalidResponseError: response not valid.
        """
        entries = None
        try:
            entries = iter(response["entries"])
        except (TypeError, KeyError) as e:
            raise InvalidResponseError("%s returned invalid data: expected "
                                       "an array of entries, got %s\n%s)" %
                                       (self.__req.uri, response, e))
        expected_response_size = end - start + 1
        response_size = len(response["entries"])
        # Logs MAY honor requests where 0 <= "start" < "tree_size" and
        # "end" >= "tree_size" by returning a partial response covering only
        # the valid entries in the specified range.
        # Logs MAY restrict the number of entries that can be retrieved per
        # "get-entries" request.  If a client requests more than the
        # permitted number of entries, the log SHALL return the maximum
        # number of entries permissible. (RFC 6962)
        #
        # Therefore, we cannot assume we get exactly the expected number of
        # entries. However if we get none, or get more than expected, then
        # we discard the response and raise.
        if not response_size or response_size > expected_response_size:
            raise InvalidResponseError(
                "%s returned invalid data: requested %d entries, got %d "
                "entries" % (self.__req.uri, expected_response_size,
                             response_size))

        # If any one of the entries has invalid json format, this raises.
        return [self.__json_entry_to_response(e) for e in entries]

    def get_entries(self, start, end, batch_size=0):
        """Retrieve log entries.

        Args:
            start     : index of first entry to retrieve.
            end       : index of last entry to retrieve.
            batch_size: max number of entries to fetch in one go.

        Yields:
            ct.proto.client_pb2.EntryResponse protos.

        Raises:
            HTTPError, HTTPClientError, HTTPServerError: connection failed,
                or returned an error. HTTPClientError can happen when
                [start, end] is not a valid range for this log.
            InvalidRequestError: invalid request range (irrespective of log).
            InvalidResponseError: server response is invalid for the given
                                  request
        Caller is responsible for ensuring that (start, end) is a valid range
        (by retrieving an STH first), otherwise a HTTPClientError may occur.
        """
        # Catch obvious mistakes here.
        if start < 0 or end < 0 or start > end:
            raise InvalidRequestError("Invalid range [%d, %d]" % (start, end))

        batch_size = batch_size or FLAGS.entry_fetch_batch_size
        while start <= end:
            # Note that an HTTPError may occur here if the log does not have the
            # requested range of entries available. RFC 6962 says:
            # "Any errors will be returned as HTTP 4xx or 5xx responses, with
            # human-readable error messages."
            # There is thus no easy way to distinguish this case from other
            # errors.
            first = start
            last = min(start + batch_size - 1, end)
            response = self.__req.get_json_response(
                self._GET_ENTRIES_PATH, params={"start": first, "end": last})
            valid_entries = self.__validated_entry_response(first, last,
                                                            response)
            for entry in valid_entries:
                yield entry
            # If we got less entries than requested, then we don't know whether
            # the log imposed a batch limit or ran out of entries, so we keep
            # trying until we get all entries, or an error response.
            start += len(valid_entries)

    def get_sth_consistency(self, old_size, new_size):
        """Retrieve a consistency proof.

        Args:
            old_size  : size of older tree.
            new_size  : size of newer tree.

        Returns:
            list of raw hashes (bytes) forming the consistency proof

        Raises:
            HTTPError, HTTPClientError, HTTPServerError: connection failed,
                or returned an error. HTTPClientError can happen when
                (old_size, new_size) are not valid for this log (e.g. greater
                than the size of the log).
            InvalidRequestError: invalid request size (irrespective of log).
            InvalidResponseError: server response is invalid for the given
                                  request
        Caller is responsible for ensuring that (old_size, new_size) are valid
        (by retrieving an STH first), otherwise a HTTPClientError may occur.
        """
        if old_size > new_size:
            raise InvalidRequestError(
                "old > new: %s >= %s" % (old_size, new_size))

        if old_size < 0 or new_size < 0:
            raise InvalidRequestError(
                "both sizes must be >= 0: %s, %s" % (old_size, new_size))

        # don't need to contact remote server for trivial proofs:
        # - empty tree is consistent with everything
        # - everything is consistent with itself
        if old_size == 0 or old_size == new_size:
            return []

        response = self.__req.get_json_response(
            self._GET_STH_CONSISTENCY_PATH,
            params={"first": old_size, "second": new_size})

        try:
            consistency = [base64.b64decode(u) for u in response["consistency"]]
        except (TypeError, ValueError, KeyError) as e:
            raise InvalidResponseError(
                "%s returned invalid data: expected a base64-encoded "
                "consistency proof, got %s"
                "\n%s" % (self.__req.uri, response, e))

        return consistency

    def get_proof_by_hash(self, leaf_hash, tree_size):
        """Retrieve an audit proof by leaf hash.

        Args:
            leaf_hash: hash of the leaf input (as raw binary string).
            tree_size: size of the tree on which to base the proof.

        Returns:
            a client_pb2.ProofByHashResponse containing the leaf index
            and the Merkle tree audit path nodes (as binary strings).

        Raises:
            HTTPError, HTTPClientError, HTTPServerError: connection failed,
            HTTPClientError can happen when leaf_hash is not present in the
                log tree of the given size.
            InvalidRequestError: invalid request (irrespective of log).
            InvalidResponseError: server response is invalid for the given
                                  request.
        """
        if tree_size <= 0:
            raise InvalidRequestError("Tree size must be positive (got %d)" %
                                      tree_size)

        leaf_hash = base64.b64encode(leaf_hash)
        response = self.__req.get_json_response(
            self._GET_PROOF_BY_HASH_PATH,
            params={"hash": leaf_hash, "tree_size": tree_size})

        proof_response = client_pb2.ProofByHashResponse()
        try:
            proof_response.leaf_index = response["leaf_index"]
            proof_response.audit_path.extend(
                [base64.b64decode(u) for u in response["audit_path"]])
        except (TypeError, ValueError, KeyError) as e:
            raise InvalidResponseError(
                "%s returned invalid data: expected a base64-encoded "
                "audit proof, got %s"
                "\n%s" % (self.__req.uri, response, e))

        return proof_response

    def get_entry_and_proof(self, leaf_index, tree_size):
        """Retrieve an entry and its audit proof by index.

        Args:
            leaf_index: index of the entry.
            tree_size: size of the tree on which to base the proof.

        Returns:
            a client_pb2.EntryAndProofResponse containing the entry
            and the Merkle tree audit path nodes (as binary strings).

        Raises:
            HTTPError, HTTPClientError, HTTPServerError: connection failed,
            HTTPClientError can happen when tree_size is not a valid size
                for this log.
            InvalidRequestError: invalid request (irrespective of log).
            InvalidResponseError: server response is invalid for the given
                                  request.
        """
        if tree_size <= 0:
            raise InvalidRequestError("Tree size must be positive (got %d)" %
                                      tree_size)

        if leaf_index < 0 or leaf_index >= tree_size:
            raise InvalidRequestError("Leaf index must be smaller than tree "
                                      "size (got index %d vs size %d" %
                                      (leaf_index, tree_size))

        response = self.__req.get_json_response(
            self._GET_ENTRY_AND_PROOF_PATH,
            params={"leaf_index": leaf_index, "tree_size": tree_size})

        entry_response = client_pb2.EntryAndProofResponse()
        try:
            entry_response.entry.CopyFrom(
                self.__json_entry_to_response(response))
            entry_response.audit_path.extend(
                [base64.b64decode(u) for u in response["audit_path"]])
        except (TypeError, ValueError, KeyError) as e:
            raise InvalidResponseError(
                "%s returned invalid data: expected an entry and proof, got %s"
                "\n%s" % (self.__req.uri, response, e))

        return entry_response

    def get_roots(self):
        """Retrieve currently accepted root certificates.

        Returns:
            a list of certificates (as raw binary strings).

        Raises:
            HTTPError, HTTPClientError, HTTPServerError: connection failed,
                or returned an error. For logs that honour HTTP status codes,
                HTTPClientError (a 4xx) should never happen.
            InvalidResponseError: server response is invalid for the given
                                  request.
        """
        response = self.__req.get_json_response(self._GET_ROOTS_PATH)
        try:
            return [base64.b64decode(u)for u in response["certificates"]]
        except (TypeError, ValueError, KeyError) as e:
            raise InvalidResponseError(
                "%s returned invalid data: expected a list od base64-encoded "
                "certificates, got %s\n%s" % (self.__req.uri, response, e))