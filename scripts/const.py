class Constants:
    SALT_SIZE = 32                                                              # * Размер соли
    IV_SIZE = 16                                                                # * Размер инициализирующего вектора
    HMAC_SIZE = 32                                                              # * Размер имитовставки
    KEY_SIZE = 32                                                               # * Размер ключа
    ITERATIONS = 100000                                                         # * Количество итераций (чем их больше, тем выше криптографическая сложность)

    @classmethod
    def set_salt_size(cls, size:int):
        cls.SALT_SIZE = size