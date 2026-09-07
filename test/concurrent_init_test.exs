defmodule ExDTLS.ConcurrentInitTest do
  use ExUnit.Case, async: false

  @moduletag timeout: 300_000

  test "concurrent connections complete handshakes, exchange data, and close" do
    {pkey, cert} = ExDTLS.generate_key_cert()

    1..128
    |> Task.async_stream(
      fn i ->
        opts = [dtls_srtp: true, verify_peer: true, pkey: pkey, cert: cert]
        client = ExDTLS.init([mode: :client] ++ opts)
        server = ExDTLS.init([mode: :server] ++ opts)

        {:ok, packets, _timeout} = ExDTLS.do_handshake(client)
        assert :ok = handshake({server, false}, {client, false}, packets, 20)
        assert ExDTLS.get_peer_cert(client) == cert
        assert ExDTLS.get_peer_cert(server) == cert

        for {sender, receiver} <- [{client, server}, {server, client}] do
          message = <<i::32, "concurrent DTLS round trip">>
          assert {:ok, packets} = ExDTLS.write_data(sender, message)
          assert {:ok, ^message} = feed_packets(receiver, packets)
        end

        assert {:ok, packets} = ExDTLS.close(client)
        assert {:error, :peer_closed_for_writing} = feed_packets(server, packets)
        assert {:error, :closed} = ExDTLS.write_data(client, "closed")
        :ok
      end,
      max_concurrency: min(System.schedulers_online() * 2, 32),
      ordered: false,
      timeout: 60_000
    )
    |> Enum.each(fn result -> assert {:ok, :ok} = result end)
  end

  @tag :stress
  test "many DTLS contexts can be created and driven concurrently" do
    {pkey, cert} = ExDTLS.generate_key_cert()

    1..50_000
    |> Task.async_stream(
      fn i ->
        mode = if rem(i, 2) == 0, do: :client, else: :server
        dtls = ExDTLS.init(mode: mode, dtls_srtp: true, pkey: pkey, cert: cert)

        if mode == :client do
          assert {:ok, _packets, _timeout} = ExDTLS.do_handshake(dtls)
        end

        :ok
      end,
      max_concurrency: System.schedulers_online() * 8,
      ordered: false,
      timeout: 300_000
    )
    |> Enum.each(fn result -> assert {:ok, :ok} = result end)
  end

  defp handshake({_receiver, true}, {_sender, true}, _packets, _remaining), do: :ok

  defp handshake(_receiver, _sender, _packets, 0) do
    flunk("DTLS handshake did not finish within 20 packet flights")
  end

  defp handshake({receiver, receiver_done}, {sender, sender_done}, packets, remaining) do
    case feed_packets(receiver, packets) do
      {:handshake_packets, packets, _timeout} ->
        handshake({sender, sender_done}, {receiver, receiver_done}, packets, remaining - 1)

      {:handshake_finished, _local_key, _remote_key, _profile, packets} ->
        handshake({sender, sender_done}, {receiver, true}, packets, remaining - 1)

      {:handshake_finished, _local_key, _remote_key, _profile} ->
        assert sender_done
        :ok

      result ->
        flunk("Unexpected handshake result: #{inspect(result)}")
    end
  end

  defp feed_packets(dtls, packets) do
    Enum.reduce(packets, :handshake_want_read, fn packet, previous ->
      assert previous == :handshake_want_read
      ExDTLS.handle_data(dtls, packet)
    end)
  end
end
