from Crypto.Cipher import DES, AES, DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import random
import string
import binascii

def obtener_clave_y_iv(algoritmo):
    #Se solicita al usuario la clave de cifrado
    clave = input("Ingresa la clave de cifrado (texto plano): ").encode('utf-8')

    #Se solicita el IV y se valida su longitud
    while True:
        iv_hex = input(f"Ingresa el vector de iniciación (IV) en formato hexadecimal para {algoritmo}: ")
        #Se valida que el IV (que está en hexadecimal) posea una cantidad de dígitos par
        try:
            iv = bytes.fromhex(iv_hex)
            #Se valida que posea una longitud adecuada al algoritmo
            if not es_iv_valido(iv, algoritmo):
                longitud_requerida = obtener_longitud_iv(algoritmo)
                print(f"Error: El IV para {algoritmo} debe tener una longitud de {longitud_requerida} bytes.")
                continue
            break
        #Se lanza una excepción si la longitud del IV no es par
        except ValueError:
            print("Error: El IV proporcionado no es un formato hexadecimal válido.")
    #Se solicita al usuario el texto a cifrar
    texto = input("Ingresa el texto a cifrar: ").encode('utf-8')

    #Se retorna la clave, el IV y el texto a cifrar
    return clave, iv, texto

def es_iv_valido(iv, algoritmo):
    #Se recupera la longitud de IV requerida por el algoritmo
    longitud_requerida = obtener_longitud_iv(algoritmo)

    #Retorna True si la longitud del IV proporcionada es la del algoritmo
    return len(iv) == longitud_requerida

def obtener_longitud_iv(algoritmo):
    #Se retorna la longitud requerida por el algoritmo
    if algoritmo == "DES" or algoritmo == "3DES":
        return 8  # IV de 8 bytes para DES y 3DES
    elif algoritmo == "AES-256":
        return 16  # IV de 16 bytes para AES-256
    else:
        raise ValueError("Algoritmo no soportado para validación de IV.")

def obtener_bytes_aleatorios_ascii(tamano):
    #Se generan bytes aleatorios imprimibles en ASCII, para propiciar el uso
    #en el sitio web, que sólo acepta ASCII para las claves
    bytes_imprimibles = []

    #Se repite el proceso hasta alcanzar el tamaño requerido por el algoritmo
    while len(bytes_imprimibles) < tamano:
        #Se genera una cantidad de bytes aleatorios
        random_bytes = get_random_bytes(tamano * 2)  # Generamos más bytes de los necesarios
        for byte in random_bytes:
            #Solo se añaden los bytes imprimibles (32-126 en ASCII)
            if 33 <= byte <= 126:
                bytes_imprimibles.append(byte)
            if len(bytes_imprimibles) >= tamano:
                break
    #Se retornan los bytes aleatorios
    return bytes(bytes_imprimibles[:tamano])

def ajustar_clave(clave, algoritmo):
    #Se ajusta la clave al tamaño requerido por el algoritmo
    if algoritmo == "DES":
        longitud = 8  #DES usa claves de 8 bytes
    elif algoritmo == "AES-256":
        longitud = 32  #AES-256 usa claves de 32 bytes
    elif algoritmo == "3DES":
        longitud = 24  #3DES usa claves de 24 bytes
    else:
        raise ValueError("Algoritmo no soportado.")

    if len(clave) < longitud:
        #Se completa con bytes aleatorios imprimibles en ASCII
        clave = clave + obtener_bytes_aleatorios_ascii(longitud - len(clave))
    elif len(clave) > longitud:
        #Se trunca la clave
        clave = clave[:longitud]

    return clave

def cifrar_y_descifrar(clave, iv, texto, algoritmo):
    #Se ajusta la clave al tamaño necesario
    clave_ajustada = ajustar_clave(clave, algoritmo)
    clave_ascii = clave_ajustada.decode('ascii')
    #Se imprime la clave ajustada
    print(f"\nClave ajustada (en ASCII): '{clave_ascii}'")

    if algoritmo == "DES":
        #Se crea el objeto de cifrado DES
        cipher = DES.new(clave_ajustada, DES.MODE_CBC, iv)
        texto_padded = pad(texto, DES.block_size)
        texto_cifrado = cipher.encrypt(texto_padded)
        #Descifrado
        decipher = DES.new(clave_ajustada, DES.MODE_CBC, iv)
        texto_descifrado = unpad(decipher.decrypt(texto_cifrado), DES.block_size)

    elif algoritmo == "AES-256":
        #Se crea el objeto de cifrado AES
        cipher = AES.new(clave_ajustada, AES.MODE_CBC, iv)
        texto_padded = pad(texto, AES.block_size)
        texto_cifrado = cipher.encrypt(texto_padded)
        #Descifrado
        decipher = AES.new(clave_ajustada, AES.MODE_CBC, iv)
        texto_descifrado = unpad(decipher.decrypt(texto_cifrado), AES.block_size)

    elif algoritmo == "3DES":
        #Se crea el objeto de cifrado 3DES
        cipher = DES3.new(clave_ajustada, DES3.MODE_CBC, iv)
        texto_padded = pad(texto, DES3.block_size)
        texto_cifrado = cipher.encrypt(texto_padded)
        #Descifrado
        decipher = DES3.new(clave_ajustada, DES3.MODE_CBC, iv)
        texto_descifrado = unpad(decipher.decrypt(texto_cifrado), DES3.block_size)

    else:
        raise ValueError("Algoritmo no soportado.")

    #Se devuelven los resultados
    return texto_cifrado, texto_descifrado.decode('utf-8')

def main():
    print("Selecciona el algoritmo de cifrado:")
    print("1. DES")
    print("2. AES-256")
    print("3. 3DES")

    opcion = input("Ingresa el número correspondiente a la opción: ")

    if opcion == "1":
        algoritmo = "DES"
    elif opcion == "2":
        algoritmo = "AES-256"
    elif opcion == "3":
        algoritmo = "3DES"
    else:
        print("Opción no válida.")
        return

    clave, iv, texto = obtener_clave_y_iv(algoritmo)
    texto_cifrado, texto_descifrado = cifrar_y_descifrar(clave, iv, texto, algoritmo)

    #Se muestran los resultados
    print("Texto original:", texto.decode('utf-8'))
    print("Texto cifrado (en hexadecimal):", binascii.hexlify(texto_cifrado).decode('utf-8'))
    print("Texto descifrado:", texto_descifrado)

if __name__ == "__main__":
    main()