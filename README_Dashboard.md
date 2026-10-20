Threshold Bar =
VAR _val    = SELECTEDVALUE ( Metrics[Value] )
VAR _opt    = SELECTEDVALUE ( Metrics[Optimized] )
VAR _stb    = SELECTEDVALUE ( Metrics[Stable] )
VAR _mon    = SELECTEDVALUE ( Metrics[Monitor] )
VAR _isHigh = SELECTEDVALUE ( Metrics[Target Direction] ) = ">"

-- Scale: range of value + thresholds, padded 15% each side
VAR _min  = MIN ( MIN ( _val, _opt ), MIN ( _stb, _mon ) )
VAR _max  = MAX ( MAX ( _val, _opt ), MAX ( _stb, _mon ) )
VAR _pad  = IF ( _max = _min, 1, ( _max - _min ) * 0.15 )
VAR _lo   = _min - _pad
VAR _span = ( _max + _pad ) - _lo

-- Layout (pixels)
VAR _left  = 14
VAR _barW  = 300
VAR _right = _left + _barW
VAR _barY  = 16
VAR _barH  = 14
VAR _lblY  = _barY + _barH + 11

-- Positions
VAR _xOpt = ROUND ( _left + ( _opt - _lo ) / _span * _barW, 1 )
VAR _xStb = ROUND ( _left + ( _stb - _lo ) / _span * _barW, 1 )
VAR _xMon = ROUND ( _left + ( _mon - _lo ) / _span * _barW, 1 )
VAR _xVal = ROUND ( _left + ( _val - _lo ) / _span * _barW, 1 )

-- Boundaries left to right, depending on direction
VAR _b1 = IF ( _isHigh, _xMon, _xOpt )
VAR _b2 = _xStb
VAR _b3 = IF ( _isHigh, _xOpt, _xMon )
VAR _t1 = IF ( _isHigh, _mon, _opt )
VAR _t2 = _stb
VAR _t3 = IF ( _isHigh, _opt, _mon )

-- Colors (%23 = #)
VAR _red    = "%23D64545"
VAR _yellow = "%23F2C94C"
VAR _green  = "%2327AE60"
VAR _blue   = "%232F80ED"
VAR _c1 = IF ( _isHigh, _red,    _blue )
VAR _c2 = IF ( _isHigh, _yellow, _green )
VAR _c3 = IF ( _isHigh, _green,  _yellow )
VAR _c4 = IF ( _isHigh, _blue,   _red )

VAR _rects =
    "<rect x='" & _left & "' y='" & _barY & "' width='" & ( _b1 - _left ) & "' height='" & _barH & "' fill='" & _c1 & "'/>" &
    "<rect x='" & _b1 & "' y='" & _barY & "' width='" & ( _b2 - _b1 ) & "' height='" & _barH & "' fill='" & _c2 & "'/>" &
    "<rect x='" & _b2 & "' y='" & _barY & "' width='" & ( _b3 - _b2 ) & "' height='" & _barH & "' fill='" & _c3 & "'/>" &
    "<rect x='" & _b3 & "' y='" & _barY & "' width='" & ( _right - _b3 ) & "' height='" & _barH & "' fill='" & _c4 & "'/>"

VAR _labels =
    "<text x='" & _b1 & "' y='" & _lblY & "' text-anchor='middle'>" & FORMAT ( _t1, "0.00" ) & "</text>" &
    "<text x='" & _b2 & "' y='" & _lblY & "' text-anchor='middle'>" & FORMAT ( _t2, "0.00" ) & "</text>" &
    "<text x='" & _b3 & "' y='" & _lblY & "' text-anchor='middle'>" & FORMAT ( _t3, "0.00" ) & "</text>"

VAR _marker =
    "<line x1='" & _xVal & "' x2='" & _xVal & "' y1='" & ( _barY - 3 ) & "' y2='" & ( _barY + _barH + 3 ) &
    "' stroke='%23222222' stroke-width='2.5'/>" &
    "<text x='" & _xVal & "' y='" & ( _barY - 5 ) & "' text-anchor='middle' font-weight='bold'>" &
    FORMAT ( _val, "0.00" ) & "</text>"

RETURN
IF (
    ISBLANK ( _val ),
    BLANK (),
    "data:image/svg+xml;utf8," &
    "<svg xmlns='http://www.w3.org/2000/svg' width='328' height='46' font-family='Segoe UI' font-size='10' fill='%23333333'>" &
    _rects & _labels & _marker &
    "</svg>"
)