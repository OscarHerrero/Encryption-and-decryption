from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Hash import HMAC, SHA256
from Crypto.Signature import pkcs1_15

#Symetric_____________________________________________________________Start

def encrypt_text(key, data):
    # Definición del modo, encriptación de datos y obtencion del nonce
    cipher = AES.new(key, AES.MODE_CTR)
    encrypted_text = cipher.encrypt(data)
    nonce = cipher.nonce
    
    # Guardar datos en un archivo
    with open('encrypted_data.bin', 'wb') as file:
        file.write(encrypted_text)
    
    return encrypted_text, nonce

def decrypt_text(key,encrypted_text, nonce):

    # Crear objeto de cifrado con la misma llave
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    decrypted_text = cipher.decrypt(encrypted_text)

    return decrypted_text

def symetric_encrypt_and_decrypt(data):
    # Muestra por consola del texto sin encriptar
    print('Texto sin encriptación:',data.decode())
    # Generación de llave
    key = get_random_bytes(16)
    # Encriptación de datos y escritura en archivo encrypted_data.bin
    encrypted_text, nonce = encrypt_text(key, data)
    # Muestra por consola de llave y texto encriptados
    print('Llave:', key.hex(),'\nTexto encriptado:', encrypted_text)
    # Lectura de texto encriptado
    with open('encrypted_data.bin', 'rb') as text_file:
        encrypted_text_from_file = text_file.read()
    # Desencriptación de texto usando la llave
    decrypted_text = decrypt_text(key, encrypted_text_from_file, nonce)
    # Muestra por consola del texto desencriptado encriptarcls
    print('Texto desencriptado: ', decrypted_text.decode())
    
#Symetric_____________________________________________________________End


#Asymetric____________________________________________________________Start

def create_rsa():
    try:
        key = RSA.generate(2048)
        private_key = key.export_key()
        with open('private.pem', 'wb') as f:
            f.write(private_key)

        public_key = key.publickey().export_key()
        with open('receiver.pem', 'wb') as f:
            f.write(public_key)

        print('Par de claves creado con éxito')
    except ValueError as e:
        print('Error al generar claves:',e)
    except TypeError as e:
        print('Error al generar claves:',e)

def read_private_key():
    # Lectura de clave privada en archivo private.pem
    with open('private.pem', 'rb') as key_file:
        private_key = RSA.import_key(key_file.read())

    return private_key

def sign_text(data):
    key = read_private_key()
    try:
        # Creación de objeto Hash y actualizacion con el texto proporcionado
        hash = SHA256.new(data)
        # Firma digital del hash utilizando clave privada RSA
        sign = pkcs1_15.new(key).sign(hash)
        # Guardar el resultado en archivo binario
        with open('sign.bin', 'wb') as sign_file:
            sign_file.write(sign)
        print('Archivo de firma creado con éxito')

    except ValueError as e:
        print('Error al firmar los datos:', e)
    except TypeError as e:
        print('Error al firmar los datos:', e)

def create_hash_hmac(key, data):
    # Crear objeto HMAC utilizando clave privada RSA
    hmac = HMAC.new(key.export_key(), digestmod=SHA256)
    #Actualizar el objeto HMAC con el texto proporcionado
    hmac.update(data)
    #Calcular Hash HMAC 
    hash = hmac.digest()
    return hash

def hmac_operation(data):
    # Obtener clave privada
    key = read_private_key()
    # Calcular hash
    hash = create_hash_hmac(key, data)

    try:
        # Guardar el resultado en archivo binario
        with open('hash.bin', 'wb') as hash_file:
            hash_file.write(hash)
        print('Archivo de hash creado con exito')

    except ValueError as e:
        print('Error al guardar el hash:', e)
    except TypeError as e:
        print('Error al guardar el hash:', e)
 
def verify_sign(data):
    # Lectura de archivos de firma y clave pública
    with open('sign.bin', 'rb') as sign_file:
        signature = sign_file.read()
    with open('receiver.pem', 'rb') as key_file:
        public_key = RSA.import_key(key_file.read())

    # Creación de objeto Hash y actualizacion con el texto proporcionado
    hash = SHA256.new(data)
    
    # Verificación de integridad
    try:
        pkcs1_15.new(public_key).verify(hash,signature)
        print('La firma es autentica')
    except ValueError as e:
        print('Error: la firma NO es válida o ha sido manipulada:', e)
    except TypeError as e:
        print('Error: la firma NO es válida o ha sido manipulada:', e)
        
def verify_hmac(data):
    # Lectura del valor hash HMAC desde el archivo binario
    with open('hash.bin', 'rb') as hash_file:
        hash_from_file = hash_file.read()
    # Obtener la clave privada RSA
    key = read_private_key()  
    # Calcular hash
    hash = create_hash_hmac(key, data)
    # Comparación del valor hash HMAC calculado con el valor del archivo
    try:
        if hash_from_file == hash:
            print("El valor hash HMAC es correcto y no ha sido manipulado.")
        else:
            print("El valor hash HMAC es incorrecto o ha sido manipulado.")
    except ValueError as e:
        print('Error al comparar los hash HMAC:', e)
    except TypeError as e:
        print('Error al comparar los hash HMAC:', e)

def asymetric_encrypt_and_decryp(data):
    # Creación de claves pública y privada
    create_rsa()
    # Firma de datos introducidos
    sign_text(data)
    # Operación Hmac
    hmac_operation(data)
    # Verificar firma
    verify_sign(data)
    # Verificar HMAC
    verify_hmac(data)
    
#Asymetric_____________________________________________________________End

def main():

    try:
        # Cadena de texto a firmar
        data = input('Introduzca el dato que desea encriptar:').encode()

        # Solicitar al usuario que elija el tipo de encriptación
        while True:
            print("Seleccione el tipo de encriptación:")
            print("1. Encriptación simétrica")
            print("2. Encriptación asimétrica")
            choice = input("Ingrese su elección (1 o 2): ")

            if choice == '1':
                symetric_encrypt_and_decrypt(data)
                break
            elif choice == '2':
                asymetric_encrypt_and_decryp(data)
                break
            else:
                print("Opción no válida. Por favor, seleccione 1 o 2.")
    except KeyboardInterrupt:
        print('\nSaliendo del programa')




if __name__ == '__main__':
    main()