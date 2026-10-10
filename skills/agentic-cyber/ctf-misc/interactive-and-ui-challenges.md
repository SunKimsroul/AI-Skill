# Interactive and UI challenges

Some challenges cannot be solved by reading files and sending bytes. They need something to be *watched* — a game world, a rendered display, a desktop application, a physical-looking simulation — and acted on while it changes.

This is the clearest documented weakness of automated solving. A team fielding an AI system at Codegate placed 2nd in the Junior Division and 18th overall, and the challenges it could not solve included one set inside a Minecraft environment: a human could look at the screen, move around, interact, and immediately see candidate directions, while the automated system could not. Recognising this class early and handing it over is worth more than any technique in this file.

## Recognise it fast

Treat a challenge as visual-interactive when any of these hold:

- The deliverable is a game client, an emulator world, a desktop GUI, or a VNC/RDP endpoint.
- State advances on its own — timers, physics, NPCs, animation — so a snapshot is not the whole story.
- The intended observation is *rendered*: a shader effect, a sprite arrangement, a canvas drawing, a chart, something positioned in 3D space.
- Input is spatial or continuous — aiming, dragging, walking, timing a press — rather than a string on stdin.
- The description says "join the server", "play the game", "look around", "find the room".

The cost of misclassifying is asymmetric. Spending an hour scripting against a game protocol you have not watched is common and usually wasted; asking the user to look at the screen for thirty seconds costs almost nothing.

## Decide the split immediately, and say so

Split the work along the line of what actually needs eyes:

- **The human observes and reports.** Ask for specific things: what is on screen, what changed after an action, what the room or level layout is, what text appears, where objects sit relative to each other. A short screen recording or a few screenshots is usually enough to unblock a whole line of analysis.
- **You do everything that is not visual.** Pull the client apart, read the protocol, decompile the assets, find the server endpoint, build the tooling that makes the human's job one action instead of twenty.

State this division out loud at the start rather than discovering it after an hour. "This one needs your eyes — while you look, I will do X" is a plan; silently grinding is not.

Ask for a screenshot before forming a hypothesis, not after one fails.

## Get underneath the interface where you can

The rendered surface is frequently not where the answer lives, and the layer beneath it is often ordinary work.

- **Game clients** — the assets, scripts, and network protocol are usually the real target. A Minecraft-style challenge is often a plugin or mod with an exploitable command handler; a Unity or Godot game is an asset bundle and a scripting runtime. See `ctf-reverse` for the client itself and `games-and-vms.md` for engine and VM specifics.
- **Web-rendered surfaces** — canvas, WebGL, and shader output are produced by JavaScript you can read directly. What is drawn is a consequence of code, and the code is available.
- **Network games** — once the protocol is understood, a scripted client can do what the GUI does without rendering anything, and can do it faster and more precisely than a human.
- **Anything with a server** — the server is a normal target. Flags rarely live in the rendering path.

Reach for a scripted client when the interaction is repetitive, timing-critical, or needs to run many times. Keep the human in the loop for orientation, comprehension of the scene, and deciding what is worth trying.

## Automating observation, and its limits

Where a browser or desktop is available, screen capture plus OCR handles some cases — reading a value that only exists as rendered pixels, defeating a CAPTCHA-style gate, or watching for a change. `games-and-vms-4.md` carries a worked Selenium-plus-Tesseract example, and OCR output needs cleaning before use because common confusions (`x` for `*`, `{` for `(`) will otherwise corrupt whatever you do with it.

Be honest about what this does not give you. OCR reads text; it does not tell you that the corridor bends left, that an NPC followed you, or that a texture is subtly wrong. Scene comprehension, spatial reasoning, and noticing the thing that looks *off* are exactly what a human contributes here. Automating capture does not remove the need for someone to look — it only reduces how often.

## Do not grind

The failure pattern is specific and worth naming: without visual feedback, the same unproductive direction gets explored for a long time, because nothing arrives to contradict it.

Apply the stuck-detection rules in `solve-challenge` with a shorter fuse than usual. Two attempts producing no new observable, on a challenge you have identified as visual-interactive, is enough — say plainly that this one needs eyes on it, hand over what you have established, and ask for the specific observation that would unblock you.
