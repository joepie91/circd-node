(function () {var Channel;

Channel = (function() {
  function Channel() {}

  return Channel;

})();

var Client, ClientStatus, crypto, dns, q,
  __bind = function(fn, me){ return function(){ return fn.apply(me, arguments); }; };

dns = require("dns");

q = require("q");

crypto = require("crypto");

ClientStatus = {
  "disconnected": 0,
  "lookingUp": 1,
  "connected": 2,
  "registered": 3,
  "ready": 4
};

Client = (function() {
  Client.prototype.regex_strip_carriage_return = /\r+$/;

  function Client(server, connection) {
    this.server = server;
    this.connection = connection;
    this.processWho = __bind(this.processWho, this);
    this.processUserhost = __bind(this.processUserhost, this);
    this.getIdentity = __bind(this.getIdentity, this);
    this.sendWelcome = __bind(this.sendWelcome, this);
    this.sendChallenge = __bind(this.sendChallenge, this);
    this.sendError = __bind(this.sendError, this);
    this.sendGlobalNotice = __bind(this.sendGlobalNotice, this);
    this.sendNumericNotice = __bind(this.sendNumericNotice, this);
    this.sendNumeric = __bind(this.sendNumeric, this);
    this.sendPong = __bind(this.sendPong, this);
    this.sendPing = __bind(this.sendPing, this);
    this.sendRaw = __bind(this.sendRaw, this);
    this.maskHost = __bind(this.maskHost, this);
    this.maskIP = __bind(this.maskIP, this);
    this.verifyRegistration = __bind(this.verifyRegistration, this);
    this.onMessage = __bind(this.onMessage, this);
    this.onData = __bind(this.onData, this);
    this.onDisconnected = __bind(this.onDisconnected, this);
    this.onConnectionCompleted = __bind(this.onConnectionCompleted, this);
    this.onChallengeCompleted = __bind(this.onChallengeCompleted, this);
    this.onLookupError = __bind(this.onLookupError, this);
    this.onLookupSuccess = __bind(this.onLookupSuccess, this);
    this.initialize = __bind(this.initialize, this);
    this.status = ClientStatus.disconnected;
    this.buffer = "";
  }

  Client.prototype.initialize = function() {
    this.process_map = {
      "USERHOST": [1, this.processUserhost],
      "WHO": [1, this.processWho]
    };
    this.connection.on("data", this.onData);
    this.status = ClientStatus.lookingUp;
    this.sendGlobalNotice("AUTH :*** Looking up your hostname...");
    return q.nfcall(dns.reverse, this.connection.remoteAddress).then(this.onLookupSuccess, this.onLookupError);
  };

  Client.prototype.onLookupSuccess = function(hosts) {
    var host;
    if (hosts.length === 0) {
      return this.onLookupError(null);
    }
    host = hosts[0];
    this.status = ClientStatus.connected;
    this.reverse = this.maskHost(host);
    this.real_reverse = host;
    return this.sendGlobalNotice("AUTH :*** Found your hostname");
  };

  Client.prototype.onLookupError = function(e) {
    this.status = ClientStatus.connected;
    this.reverse = this.maskIP(this.connection.remoteAddress);
    this.real_reverse = this.connection.remoteAddress;
    return this.sendGlobalNotice("AUTH :*** Could not find your hostname, using IP address instead");
  };

  Client.prototype.onChallengeCompleted = function() {
    this.status = ClientStatus.ready;
    return this.onConnectionCompleted();
  };

  Client.prototype.onConnectionCompleted = function() {
    if (this.nickname in this.server.users) {
      return this.abortConnection("Nickname is already in use.");
    }
    this.server.users[this.nickname] = this;
    return this.sendWelcome();
  };

  Client.prototype.onDisconnected = function(reason) {
    return delete this.server.users[this.nickname];
  };

  Client.prototype.onData = function(data) {
    var message, messages, _i, _len, _results;
    this.buffer += data;
    messages = this.buffer.split("\n");
    this.buffer = messages.pop();
    _results = [];
    for (_i = 0, _len = messages.length; _i < _len; _i++) {
      message = messages[_i];
      _results.push(this.onMessage(message.replace(this.regex_strip_carriage_return, "")));
    }
    return _results;
  };

  Client.prototype.onMessage = function(message) {
    var func, min_args, segments, _ref;
    segments = Util.parseMessage(message);
    segments[0] = segments[0].toUpperCase();
    if (this.status === ClientStatus.connected) {
      switch (segments[0]) {
        case "USER":
          if (segments.length < 5) {
            return this.sendError(461, "USER", "Not enough parameters.");
          } else {
            this.ident = segments[1];
            this.realname = segments[4];
            return this.verifyRegistration();
          }
          break;
        case "NICK":
          if (segments.length < 2) {
            return this.sendError(461, "NICK", "Not enough parameters.");
          } else {
            if (segments[1] in this.server.users) {
              return this.sendError(433, segments[1], "Nickname already in use.");
            } else {
              this.nickname = segments[1];
              return this.verifyRegistration();
            }
          }
          break;
        case "PONG":
          return null;
        default:
          return this.sendError(451, segments[0], "You have not registered.");
      }
    } else if (this.status === ClientStatus.registered) {
      if (segments[0] === "PONG") {
        if (segments.length < 2) {
          return this.sendError(461, "PONG", "Not enough parameters.");
        } else {
          if (segments[1] === this.challenge) {
            return this.onChallengeCompleted();
          } else {
            return this.sendError(801, segments[0], "Your challenge response PONG is incorrect.");
          }
        }
      } else {
        return this.sendError(451, segments[0], "You have not completed the challenge PING.");
      }
    } else if (this.status === ClientStatus.ready) {
      if (segments[0] === "PING") {
        if (segments.length < 2) {
          return this.sendError(461, "PONG", "Not enough parameters.");
        } else {
          return this.sendPong(segments[1]);
        }
      } else {
        if (segments[0] in this.process_map) {
          _ref = this.process_map[segments[0]], min_args = _ref[0], func = _ref[1];
          if (segments.length < min_args + 1) {
            return this.sendError(461, segments[0], "Not enough parameters.");
          } else {
            return func(segments);
          }
        } else {
          return this.sendError(421, segments[0], "Unknown command");
        }
      }
    }
  };

  Client.prototype.verifyRegistration = function() {
    if ((this.ident != null) && (this.nickname != null)) {
      this.status = ClientStatus.registered;
      return this.sendChallenge();
    }
  };

  Client.prototype.maskIP = function(ip) {
    return ip;
  };

  Client.prototype.maskHost = function(host) {
    return host;
  };

  Client.prototype.sendRaw = function(data) {
    return this.connection.write(data + "\r\n");
  };

  Client.prototype.sendPing = function(value) {
    return this.sendRaw("PING :" + value);
  };

  Client.prototype.sendPong = function(value) {
    return this.sendRaw("PONG :" + value);
  };

  Client.prototype.sendNumeric = function(numeric, message) {
    return this.sendRaw(":" + this.server.host + " " + numeric + " " + this.nickname + " " + message);
  };

  Client.prototype.sendNumericNotice = function(numeric, message) {
    return this.sendNumeric(numeric, ":" + message);
  };

  Client.prototype.sendGlobalNotice = function(message) {
    return this.sendRaw(":" + this.server.host + " NOTICE " + message);
  };

  Client.prototype.sendError = function(numeric, command, message) {
    return this.sendNumeric(numeric, "" + command + " :" + message);
  };

  Client.prototype.sendChallenge = function() {
    return q.nfcall(crypto.randomBytes, 6).then((function(_this) {
      return function(bytes) {
        bytes = bytes.toString("hex");
        _this.challenge = bytes;
        return _this.sendPing(bytes);
      };
    })(this), (function(_this) {
      return function(error) {
        return _this.disconnect(error);
      };
    })(this));
  };

  Client.prototype.sendWelcome = function() {
    this.sendNumericNotice("001", "Welcome to " + this.server.network + ", " + this.nickname + "!" + this.ident + "@" + this.real_reverse);
    this.sendNumericNotice("002", "Your host is " + this.server.host + ", running circd/0.0.1");
    this.sendNumericNotice("003", "This server has been running since unknown.");
    return this.sendNumericNotice("004", "" + this.server.host + " circd/0.0.1  ");
  };

  Client.prototype.getIdentity = function(nickname) {
    var host, ident;
    ident = this.ident;
    if (nickname === this.nickname) {
      host = this.real_reverse;
    } else {
      host = this.reverse;
    }
    return "" + ident + "@" + host;
  };

  Client.prototype.processUserhost = function(segments) {
    var i, identity, nickname, nicknames, pads, remaining_slots, responses, _i, _j, _len;
    nicknames = segments.slice(1);
    responses = [];
    for (_i = 0, _len = nicknames.length; _i < _len; _i++) {
      nickname = nicknames[_i];
      identity = this.getIdentity(nickname);
      responses.push("" + nickname + "=+" + identity);
    }
    remaining_slots = 5 - segments.length;
    if (remaining_slots >= 2) {
      pads = remaining_slots - 1;
      for (i = _j = 0; 0 <= pads ? _j <= pads : _j >= pads; i = 0 <= pads ? ++_j : --_j) {
        responses.push("");
      }
    }
    return this.sendNumeric("302", responses.join(" "));
  };

  Client.prototype.processWho = function(segments) {
    var modifiers, query, _ref;
    query = segments[0];
    return modifiers = (_ref = segments[1].split()) != null ? _ref : [];
  };

  return Client;

})();

var Server, net,
  __bind = function(fn, me){ return function(){ return fn.apply(me, arguments); }; };

net = require("net");

Server = (function() {
  function Server() {
    this.onError = __bind(this.onError, this);
    this.onConnected = __bind(this.onConnected, this);
    this.start = __bind(this.start, this);
    this.bind = __bind(this.bind, this);
    this.bindings = [];
    this.clients = [];
    this.users = {};
    this.channels = {};
    this.host = "localhost";
    this.network = "Cryto IRC";
  }

  Server.prototype.bind = function(bind_ip, port, tls, options) {
    if (tls == null) {
      tls = false;
    }
    if (options == null) {
      options = {};
    }
    return this.bindings.push({
      bind_ip: bind_ip,
      port: port,
      tls: tls,
      options: options
    });
  };

  Server.prototype.start = function() {
    var binding, _i, _len, _ref, _results;
    _ref = this.bindings;
    _results = [];
    for (_i = 0, _len = _ref.length; _i < _len; _i++) {
      binding = _ref[_i];
      if (binding.tls) {
        binding.socket = tls.createServer(this.onConnected, binding.options);
      } else {
        binding.socket = net.createServer(this.onConnected, binding.options);
      }
      binding.socket.on("listening", (function(_this) {
        return function() {
          return console.log("Listening on " + binding.bind_ip + ":" + binding.port);
        };
      })(this));
      binding.socket.on("error", (function(_this) {
        return function(e) {
          return _this.onError(binding, e);
        };
      })(this));
      _results.push(binding.socket.listen(binding.port, binding.bind_ip));
    }
    return _results;
  };

  Server.prototype.onConnected = function(connection) {
    var client;
    client = new Client(this, connection);
    this.clients.push(client);
    return client.initialize();
  };

  Server.prototype.onError = function(binding, e) {
    if (e.code === "EADDRINUSE") {
      return binding.socket.close();
    }
  };

  return Server;

})();

var Util;

Util = {
  nickname_regex: /[a-zA-Z\[\]\\`_^{|}][a-zA-Z0-9\[\]\\`_^{|}-]*/,
  parseMessage: function(message) {
    var halves, segment, segments;
    if (message.substring(0, 1) === ":") {
      message = message.split(" ").slice(1).join(" ");
    }
    halves = Util.singleSplit(message, ":");
    if (halves.length > 1) {
      segments = halves[0].split(" ").concat([halves[1]]);
    } else {
      segments = halves[0].split(" ");
    }
    return (function() {
      var _i, _len, _results;
      _results = [];
      for (_i = 0, _len = segments.length; _i < _len; _i++) {
        segment = segments[_i];
        if (segment.trim() !== "") {
          _results.push(segment.trim());
        }
      }
      return _results;
    })();
  },
  singleSplit: function(string, separator) {
    var index;
    index = string.indexOf(separator);
    if (index >= 0) {
      return [string.slice(0, index), string.slice(index + 1)];
    } else {
      return [string];
    }
  },
  splitChannelNames: function(names) {
    return names.split(",");
  },
  isChannelName: function(name) {
    var _ref;
    return (_ref = name.substring(0, 1)) === "&" || _ref === "#" || _ref === "+" || _ref === "!";
  },
  isValidChannelName: function(name) {
    var char, _i, _len, _ref;
    _ref = [" ", ",", "\x00", "\x07", "\r", "\n"];
    for (_i = 0, _len = _ref.length; _i < _len; _i++) {
      char = _ref[_i];
      if (name.indexOf(char) >= 0) {
        return false;
      }
    }
    return Util.isChannelName(name);
  },
  isValidNickname: function(name) {
    return Util.nickname_regex.test(name);
  },
  toLowercaseIRC: function(string) {

    /*
    			http://tools.ietf.org/html/rfc2812#section-2.2
    			
    			"Because of IRC's Scandinavian origin, the characters {}|^ are
    			 considered to be the lower case equivalents of the characters []\~,
    			 respectively. This is a critical issue when determining the
    			 equivalence of two nicknames or channel names."
    			
    			Yeah, don't ask me. I don't understand either.
     */
    return string.toLowercase().replace("[", "{").replace("]", "}").replace("\\", "|").replace("~", "^");
  },
  filterByMask: function(collection, mask, property) {
    var escaped, item, re;
    if (property == null) {
      property = null;
    }
    escaped = Util.escapeCharacters(mask, ["\\", "^", "$", "{", "}", "[", "]", "(", ")", ".", "|", "+", "<", ">", "-", "&"]);
    re = new RegExp(escaped.replace("*", ".*").replace("?", "."));
    if (property != null) {
      return ((function() {
        var _i, _len, _results;
        if (re.test(item[property])) {
          _results = [];
          for (_i = 0, _len = collection.length; _i < _len; _i++) {
            item = collection[_i];
            _results.push(item);
          }
          return _results;
        }
      })());
    } else {
      return ((function() {
        var _i, _len, _results;
        if (re.test(item)) {
          _results = [];
          for (_i = 0, _len = collection.length; _i < _len; _i++) {
            item = collection[_i];
            _results.push(item);
          }
          return _results;
        }
      })());
    }
  },
  escapeCharacters: function(string, characters) {
    var character, _i, _len;
    for (_i = 0, _len = characters.length; _i < _len; _i++) {
      character = characters[_i];
      string = string.replace(character, "\#{character}");
    }
    return string;
  }
};

var server;

server = new Server();

server.bind(null, 6667);

server.start();
; })();