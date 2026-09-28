╔══════════════════════════════════════════════════════════════╗
║   HidraNet — Presence Monitor                                ║
╚══════════════════════════════════════════════════════════════╝

WHAT IT IS
  A panel that counts how many HidraNet clients are currently
  emitting a presence signal.

HOW TO OPEN
  1. Extract this folder.
  2. Double-click "Open Panel.bat"
     (or open "index.html" in Chrome or Edge).

WHAT YOU SEE
  • Large number = clients signalling right now.
  • Peak = the highest value seen since you opened the panel.

READ THIS BEFORE TRUSTING THE NUMBER
  This panel is NOT private, and the number is NOT a reliable
  metric. We would rather say so than let you assume otherwise.

  • The presence channel sits on a PUBLIC MQTT broker. Anyone in
    the world can subscribe to it and count exactly what you count
    here. There is no password because there is nothing to protect:
    the channel is open.

  • Anyone can also PUBLISH false signals to it. The count can be
    inflated by whoever wants to. Treat it as indicative.

  • It counts clients with the application OPEN, not users of the
    network. Closing the application makes the count drop.

WHAT WAS REMOVED, AND WHY
  Earlier versions of this panel showed a world map, a breakdown by
  country, and a count per room.

  That worked because HidraChat obtained each user's approximate
  location (by IP, through an external service) and published it on
  the public channel, together with the identifier of the room that
  person was in.

  It meant anyone watching the channel could locate every user at
  city level and, by grouping on the room identifier, work out who
  was talking to whom — without breaking any encryption. Message
  content was protected; the metadata was in plain view.

  In a privacy tool that is unacceptable, so:
    • location collection was removed entirely;
    • the signal now carries only an ephemeral identifier and a
      timestamp;
    • the map and the lists were taken out, because they depended on
      data we stopped collecting — and should never have collected.

  A poorer panel and protected users is the right trade.

WHAT THE SIGNAL CONTAINS TODAY
    { "cid": "<ephemeral identifier>", "t": <timestamp> }
  And nothing else. No location, no room, no name, no messages.

REQUIREMENTS
  • An internet connection.
  • Clients need a current version of HidraNet.

──────────────────────────────────────────────────────────────────
  HidraNet — decentralised network · presence monitor
