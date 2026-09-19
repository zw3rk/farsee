# All-black framebuffer handling

A structurally valid session can deliver a framebuffer whose RGB values are
all zero. That output can reflect remote desktop state, login state, or a
temporary peer condition. Pixel colour alone does not identify the cause.

The product tracks consecutive black frames for an operator hint. Capture and
evidence writers reject a scene-free frame before opening or modifying their
output. Protocol processing continues unless another contract reports an
error.

Tests must treat all-black input as a valid framebuffer value and separately
verify that evidence writers fail closed.
