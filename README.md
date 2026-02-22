# Interpoll

A decentralized polling platform. Votes are recorded on a local blockchain, poll data lives in a distributed database (GunDB), and peers find each other through a lightweight WebSocket relay. Everything works offline -- sync happens when a connection is available. Data is basically unerasable, because as soon as one peer is back online, whole data is restored.
<img width="1918" height="966" alt="image" src="https://github.com/user-attachments/assets/31717176-eb42-43b2-8200-8da9cf022550" />



We provide websocket and GunDB server at https://interpoll.onrender.com and https://interpoll2.onrender.com The code on those relays is proprietary due to security concerns, but the client is open source, and we have comprehensive specs to code your own relay while we develop a community version.

Spec is located at spec.md

Prod client with configuration to default backend and basically main instance is at https://endless.sbs

I have provided Gun and WSS based on specs i did. This is vibe coded and should be cleaned up before being used for anything imported. Hand coded version is for prod and is withheld due to security concerns.
