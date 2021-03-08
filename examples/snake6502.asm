;  ___           _        __ ___  __ ___
; / __|_ _  __ _| |_____ / /| __|/  \_  )
; \__ \ ' \/ _` | / / -_) _ \__ \ () / /
; |___/_||_\__,_|_\_\___\___/___/\__/___|

; Change direction: W A S D

; Offsets of zero page variables
define appleL         $00 ; location of apple L
define appleH         $01 ; location of apple H
define snakeDirection $02 ; direction of snake movement
define snakeLength    $03 ; current snake length in bytes
define snakeHeadL     $10 ; location of snake head L
define snakeHeadH     $11 ; location of snake head H
define snakeBodyStart $12 ; start of snake body byte pairs

; Directions
define movingUp    1
define movingRight 2
define movingDown  4
define movingLeft  8

; Keys
define ASCII_w     $77
define ASCII_a     $61
define ASCII_s     $73
define ASCII_d     $64

; System variables
define sysRandom      $fe
define sysLastKey     $ff

  jsr init
  jsr loop

init:
  jsr initSnake
  jsr generateApplePosition
  rts

initSnake:
  lda #movingRight ;start direction
  sta snakeDirection

  lda #4 ; start length (2 segments of 2 bytes per segment)
  sta snakeLength

  lda #$11
  sta snakeHeadL

  lda #$10
  sta snakeBodyStart

  lda #$0f
  sta $14 ; body segment 1 offset H

  lda #$04
  sta snakeHeadH
  sta $13 ; body segment 1 offset L
  sta $15 ; body segment 2 offset L

  ; snakeHead will be $411 = $200 + $200 + $11
  ;                           (1)    (2)   (3)
  ; 1) screen offset
  ; 2) $20 (32 pixels per row) * $10 (row 16)
  ; 3) $11 (column 17)
  ;
  ; body segments are offset a little bit to avoid erasing the head

  rts

generateApplePosition:
  ; generate a random position for apple
  ; position should be between $200-$5ff (screen = 32 x 32 pixels = 1024 or $400 hexa)

  lda sysRandom
  sta appleL ; store low byte between 00-ff

  lda sysRandom
  and #$03   ; mask only 2 lowest bits 00-03
  clc        ; clear carry bit before add
  adc #$02   ; add 2 to shift range to 02-05
  sta appleH ; store high byte value between 02-05
  rts
  
loop:
  jsr readkeys
  jsr checkCollision
  jsr updateSnake
  jsr drawApple
  jsr drawSnake
  jsr spinWheels
  jmp loop

drawApple:
  ldy #0          ; offset 0
  lda sysRandom   ; choose a random color (blink effect)
  sta (appleL),y  ; draw apple as a single pixel at memory offset pointed by appleL + appleH (use indirect indexed)
  rts

drawSnake:
  ldx snakeLength    ; point to end of snake body
  lda #0             ; 0 = black
  sta (snakeHeadL,x) ; erase end of tail (use indexed indirect addressing)

  ldx #0
  lda #1             ; 1 = white
  sta (snakeHeadL,x) ; draw snake head
  rts

drawDeadSnake:
  ldx snakeLength    ; point to end of snake body
  lda #4             ; 2 = pink
loopDead:
  sta (snakeHeadL,x) ; erase end of tail (use indexed indirect addressing)
  dex
  bne loopDead
  rts

readkeys:
  lda sysLastKey     ; load current pressed key and compare to WASD ascii codes
  cmp #ASCII_w
  beq upKey
  cmp #ASCII_a
  beq leftKey
  cmp #ASCII_s
  beq downKey
  cmp #ASCII_d
  beq rightKey
  rts
upKey:
  lda #movingDown    ; if current move is down, can't go up, so ignore
  bit snakeDirection
  bne illegalMove
  lda #movingUp      ; else, continue setting direction
  sta snakeDirection
  rts
leftKey:
  lda #movingRight
  bit snakeDirection
  bne illegalMove
  lda #movingLeft
  sta snakeDirection
  rts  
downKey:
  lda #movingUp
  bit snakeDirection
  bne illegalMove
  lda #movingDown
  sta snakeDirection
  rts
rightKey:
  lda #movingLeft
  bit snakeDirection
  bne illegalMove
  lda #movingRight
  sta snakeDirection
  rts
illegalMove:
  rts
  
updateSnake:

  ; memory layout of snake body segments
  ;
  ;               snakeBodyStart
  ;               |
  ;               v
  ; ... |   |   |   |   |   |   | ... up to $10 + snakeLength bytes
  ;      $10 $11 $12 $13 $14 $15
  ;       ^
  ;       |
  ;       snakeHeadL

  ; rotate right all body segments
  ldx snakeLength       ; get snakeLength-1 to point
  dex                   ; to the last byte of the snake body
  txa                   ; ????
updateLoop:
  lda snakeHeadL,x      ; rotate all segments
  sta snakeBodyStart,x  ; to the next position on the body
  dex                   ; doing it from right to left (to avoid overwriting)
  bpl updateLoop        ; repeat while > 0

  ; find out snake direction
  ; by shifting direction bit to the right 1 bit at a time
  ; the right most shift will be shifted into the carry flag
  ; bcs will check if the carry flag is set and branch to the appropriate position
  lda snakeDirection
  lsr
  bcs up
  lsr
  bcs right
  lsr
  bcs down
  lsr
  bcs left
up:
  lda snakeHeadL
  sec               ; always set the carry flag before subtraction
  sbc #$20          ; subtract $20 (32 pixels) from position to move head one line up
  sta snakeHeadL
  bcc upup          ; if carry set is clear, then subtraction ended "borrowing"
  rts
upup:
  dec snakeHeadH    ; decrease (borrow)
  lda #$1
  cmp snakeHeadH    ; if value is $01xx then the snake head is below screen base address $0200
  beq collision     ; so jump to collision
  rts
right:
  inc snakeHeadL    ; increment location by 1 (move right)
  lda #$1f
  bit snakeHeadL    ; bitwise AND with 00011111 ($1f) to check if column is above $20 (32)
  beq collision
  rts
down:
  lda snakeHeadL
  clc               ; always clear the carry flag before addition
  adc #$20          ; add $20 (32 pixels) from position to move head one line down
  sta snakeHeadL
  bcs downdown      ; if carry set is set, then addition ended "carrying"
  rts
downdown:
  inc snakeHeadH    ; increment (carry)
  lda #$6
  cmp snakeHeadH    ; if location is $06xx then snake reached end of screen space ($0200 - $05ff)
  beq collision
  rts
left:
  dec snakeHeadL    ; decrement location by 1 (move left)
  lda snakeHeadL
  and #$1f
  cmp #$1f          ; bitwise AND with 00011111 ($1f) to check if column went under $00
  beq collision
  rts
collision:
  jmp gameOver

checkCollision:
  jsr checkAppleCollision
  jsr checkSnakeCollision
  rts

checkAppleCollision:
  lda appleL
  cmp snakeHeadL
  bne doneCheckAppleCollision
  lda appleH
  cmp snakeHeadH
  bne doneCheckAppleCollision
  
  ; eat apple (increase snake length by 1 - each segment = 2 bytes)
  inc snakeLength
  inc snakeLength
  jsr generateApplePosition
doneCheckAppleCollision:
  rts

checkSnakeCollision:
  ldx #2                    ; start with second segment since snake can't collide with head
snakeCollisionLoop:
  lda snakeHeadL,x          ; check if current segment low byte collided with head
  cmp snakeHeadL
  bne continueCollisionLoop ; no, go check the next segment
  
  lda snakeHeadL,x          ; check if high byte also collided
  cmp snakeHeadL
  beq didCollide

continueCollisionLoop:
  inx                       ; advance to next segment
  inx
  cpx snakeLength           ; check if last segment reached
  beq didntCollide
  jmp snakeCollisionLoop
  
didCollide:
  jmp gameOver

didntCollide:
  rts
  
spinWheels:
  lda #0            ; start countdown with $00, first decrement will wrap back to $ff
  sec
  sbc snakeLength   ; TEST - shorten loop if snake gets bigger...
  sec
  sbc snakeLength   ; TEST - shorten loop if snake gets bigger...
  
spinloop:
  nop               ; wait...
  nop
  dex               
  bne spinloop      ; until it reaches 0
  rts

gameOver:
  jsr drawDeadSnake
