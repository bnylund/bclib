#include "bclib++.h"

BCLib::BCLib(const char* game, const char* name, std::function<void(std::string)> log) : name(name), game(game), log(log), loggedIn(std::make_shared<bool>(false)), cur_server(std::make_shared<std::string>("")) {
    server.config.port = 8477;
    LOG("Initialized!");
}

void BCLib::StartCBServer() {
    using namespace std::placeholders;
    using namespace std;

    LOG("Starting WebSocket server");
    auto& ep = server.endpoint["^/bclib/?$"];

    ep.on_message = [&](shared_ptr<WsServer::Connection> connection, shared_ptr<WsServer::InMessage> in_message) {
        auto out_message = in_message->string();

        cout << "Server: Message received: \"" << out_message << "\" from " << connection.get() << endl;

        if (out_message == "stop") {
            LOG("Closing from websocket.");

            // connection->send is an asynchronous function
            connection->send("STOPPING", [&](const SimpleWeb::error_code& ec) {
                if (ec) {
                    LOG("Server: Error sending stopping message. " +
                        // See http://www.boost.org/doc/libs/1_55_0/doc/html/boost_asio/reference.html, Error Codes for error code meanings
                        "Error: " + to_string(ec.value()) + ", error message: " + ec.message());
                }
                Stop();
            });
        }
        else if (out_message.find("connect ", 0) == 0) {
            std::vector<std::string> args = split(out_message, " ");
            if (args.size() >= 2) {
                Disconnect();
                Connect(args[1], args.size() >= 3 ? args[2] : "");
                connection->send("CONNECT " + args[1], [&](const SimpleWeb::error_code& ec) {});
            }
            else {
                connection->send("CONNECT_ERROR NOT_ENOUGH_ARGS", [&](const SimpleWeb::error_code& ec) {});
            }
        }
    };

    ep.on_open = [&](shared_ptr<WsServer::Connection> connection) {
        LOG("Server: Opened connection " + connection->remote_endpoint().address().to_string() + ":" + to_string(connection->remote_endpoint().port()));
        connection->send("{\"name\":\""+std::string(name)+"\",\"game\":\""+game+"\"}", [&](const SimpleWeb::error_code &ec) {});
    };

    // See RFC 6455 7.4.1. for status codes
    ep.on_close = [&](shared_ptr<WsServer::Connection> connection, int status, const string& /*reason*/) {
        LOG("Server: Closed connection " + connection->remote_endpoint().address().to_string() + ":" + to_string(connection->remote_endpoint().port()) + "with status code " + to_string(status));
    };

    // Can modify handshake response headers here if needed
    ep.on_handshake = [&](shared_ptr<WsServer::Connection> /*connection*/, SimpleWeb::CaseInsensitiveMultimap& /*response_header*/) {
        return SimpleWeb::StatusCode::information_switching_protocols; // Upgrade to websocket
    };

    // See http://www.boost.org/doc/libs/1_55_0/doc/html/boost_asio/reference.html, Error Codes for error code meanings
    ep.on_error = [&](shared_ptr<WsServer::Connection> connection, const SimpleWeb::error_code& ec) {
        LOG("Server: Error in connection " + connection->remote_endpoint().address().to_string() + ":" + to_string(connection->remote_endpoint().port()) + ". Error: " + to_string(ec.value()) + ", error message: " + ec.message());
    };

    server.start([&](unsigned short port) {
        LOG("Server listening on port " + to_string(port));
    });
}

void BCLib::StopCBServer() {
    LOG("Stopping server");
    server.stop();
}

void BCLib::Connect(std::string server, std::string token) {
    h.clear_con_listeners();
    h.clear_socket_listeners();
    h.set_reconnect_delay(1000);
    h.set_reconnect_delay_max(5000);
    h.set_reconnect_attempts(2);
    h.set_reconnecting_listener([&, server]() {
        LOG("Attempting to reconnect to '" + server + "'...");
        *loggedIn = false;
    });
    h.set_fail_listener([&]() {
        LOG("Socket failed.");
        *loggedIn = false;
    });
    h.set_open_listener([&, server, token]() {
        *loggedIn = false;
        LOG("Socket connected");

        // If a token was passed into connect, use it to directly log in. Otherwise display website.
        if (token.size() == 0) {
            h.socket()->emit("login", sio::message::list("PLUGIN"), [&, server](const sio::message::list& list) {
                std::string res = list[0]->get_string();
                std::string site = server + res;
                LOG("RESPONSE: " + res);
                LOG("Total: " + site);

                // Open default browser
                ShellExecuteA(0, 0, site.c_str(), 0, 0, SW_SHOW);
            });
        }
        else {
            // Login with token
            h.socket()->emit("login", sio::message::list("PLUGIN"), [&, server](const sio::message::list& list) {
                std::string res = list[0]->get_string();
                std::string site = server + res;
                LOG("RESPONSE: " + res);
                LOG("Total: " + site);

                // Open default browser
                ShellExecuteA(0, 0, site.c_str(), 0, 0, SW_SHOW);
            });
        }

        h.socket()->on("logged_in", [&](const std::string& name, sio::message::ptr const& message, bool need_ack, sio::message::list& ack_message) {
            *loggedIn = true;
            h.set_reconnect_attempts(3600);
        });
    });
    h.set_close_listener([&](int const& reason) {
        *loggedIn = false;
        LOG("Socket closed");
    });
    LOG("Attempting to connect to " + server);
    h.connect(server);
    *cur_server = server;
}

void BCLib::Disconnect() {
    if (h.opened()) {
        LOG("Disconnecting from server.");
        h.socket()->off_all();
        h.clear_con_listeners();
        h.clear_socket_listeners();
        h.set_reconnect_attempts(0);
        h.set_reconnect_delay(0);
        clock_t time_req = clock();
        h.sync_close();
        time_req = clock() - time_req;
        LOG("Disconnected. ("+std::to_string(((float)time_req/CLOCKS_PER_SEC)) + "s)");
    }
    else {
        LOG("Client already disconnected.");
    }
}

void BCLib::Stop() {
    StopCBServer();
    Disconnect();
}

void BCLib::SendEvent(std::string eventName, const json& jsawn) {
	json event;
	event["game"] = game;
	event["event"] = eventName;
	event["data"] = jsawn;

	if (h.opened()) {
		h.socket()->emit("game event", event.dump());
	}
}