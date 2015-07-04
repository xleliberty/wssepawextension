# Wsse Paw extension

## An extension for paw rest client (https://luckymarmot.com/paw/) for Wsse header automatic generation

This class is essentially an ES6 port of V. Ruiz work ( wsse-js https://github.com/vrruiz/wsse-js )

To use it, install babel and you can then publish it with:

babel WsseHeader -o fr.eliberty.PawExtensions.WsseHeader/WsseHeader.js

You can then copy this dir into your Paw extension dir:
cp -r fr.eliberty.PawExtensions.WsseHeader ~/Library/Containers/com.luckymarmot.Paw/Data/Library/Application Support/com.luckymarmot.Paw/Extensions
