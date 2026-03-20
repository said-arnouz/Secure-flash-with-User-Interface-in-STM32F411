################################################################################
# Automatically-generated file. Do not edit!
# Toolchain: GNU Tools for STM32 (9-2020-q2-update)
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../STM32_Cryptographic/legacy_v3/src/rsa/legacy_v3_rsa.c 

OBJS += \
./STM32_Cryptographic/legacy_v3/src/rsa/legacy_v3_rsa.o 

C_DEPS += \
./STM32_Cryptographic/legacy_v3/src/rsa/legacy_v3_rsa.d 


# Each subdirectory must supply rules for building sources it contributes
STM32_Cryptographic/legacy_v3/src/rsa/legacy_v3_rsa.o: ../STM32_Cryptographic/legacy_v3/src/rsa/legacy_v3_rsa.c STM32_Cryptographic/legacy_v3/src/rsa/subdir.mk
	arm-none-eabi-gcc "$<" -mcpu=cortex-m4 -std=gnu11 -g3 -DDEBUG -DUSE_HAL_DRIVER -DSTM32F411xE -c -I../Core/Inc -I../Drivers/STM32F4xx_HAL_Driver/Inc -I../Drivers/STM32F4xx_HAL_Driver/Inc/Legacy -I../Drivers/CMSIS/Device/ST/STM32F4xx/Include -I../Drivers/CMSIS/Include -I"C:/Users/HP/Documents/work_space/Embedded_Secure_Encryp_Comp/Bootloader/STM32_Cryptographic/include" -I"C:/Users/HP/Documents/work_space/Embedded_Secure_Encryp_Comp/Bootloader/STM32_Cryptographic/legacy_v3/include" -I"C:/Users/HP/Documents/work_space/Embedded_Secure_Encryp_Comp/Bootloader/STM32_Cryptographic/include/hash" -I"C:/Users/HP/Documents/work_space/Embedded_Secure_Encryp_Comp/Bootloader/STM32_Cryptographic/include/ecc" -I"C:/Users/HP/Documents/work_space/Embedded_Secure_Encryp_Comp/Bootloader/STM32_Cryptographic/legacy_v3/include/hash" -I"C:/Users/HP/Documents/work_space/Embedded_Secure_Encryp_Comp/Bootloader/STM32_Cryptographic/legacy_v3/include/ecc" -I"C:/Users/HP/Documents/work_space/Embedded_Secure_Encryp_Comp/Bootloader/STM32_Cryptographic/legacy_v3/src/ecc" -I"C:/Users/HP/Documents/work_space/Embedded_Secure_Encryp_Comp/Bootloader/STM32_Cryptographic/legacy_v3/src/hash" -I"C:/Users/HP/Documents/work_space/Embedded_Secure_Encryp_Comp/Bootloader/STM32_Cryptographic/legacy_v3/src" -I"C:/Users/HP/Documents/work_space/Embedded_Secure_Encryp_Comp/Bootloader/STM32_Cryptographic/legacy_v3/include/cipher" -I"C:/Users/HP/Documents/work_space/Embedded_Secure_Encryp_Comp/Bootloader/STM32_Cryptographic/legacy_v3/src/cipher" -I"C:/Users/HP/Documents/work_space/Embedded_Secure_Encryp_Comp/Bootloader/STM32_Cryptographic/include/cipher" -O0 -ffunction-sections -fdata-sections -Wall -fstack-usage -MMD -MP -MF"STM32_Cryptographic/legacy_v3/src/rsa/legacy_v3_rsa.d" -MT"$@" --specs=nano.specs -mfpu=fpv4-sp-d16 -mfloat-abi=hard -mthumb -o "$@"

