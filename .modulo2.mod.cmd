savedcmd_/home/mauricio/modulo2/modulo2.mod := printf '%s\n'   modulo2.o | awk '!x[$$0]++ { print("/home/mauricio/modulo2/"$$0) }' > /home/mauricio/modulo2/modulo2.mod
