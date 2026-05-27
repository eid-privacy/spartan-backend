# ACIR

```
Compiled ACIR for main:
func 0
private parameters: [w0]
public parameters: []
return values: []
ASSERT w1 = 40902200210088653215032584946694356296222563095503428277299570638400093548589
BLACKBOX::EMBEDDED_CURVE_ADD input1: [w0, w1, 0], input2: [w0, w1, 0], predicate: 1, outputs: [w2, w3, w4]
ASSERT w2 = 10387378418920170991901925379757851472848140451366402977927462146922501327331
ASSERT w3 = 13820003873047333813317371183515203145343686146200578295967632643564487086665
```

# Prover inputs

```
InputWire { public: false, witness: Witness(0), value: FieldElement(3) }
InputWire { public: false, witness: Witness(1), value: FieldElement(40902200210088653215032584946694356296222563095503428277299570638400093548589) }
InputWire { public: false, witness: Witness(2), value: FieldElement(10387378418920170991901925379757851472848140451366402977927462146922501327331) }
InputWire { public: false, witness: Witness(3), value: FieldElement(13820003873047333813317371183515203145343686146200578295967632643564487086665) }
InputWire { public: false, witness: Witness(4), value: FieldElement(0) }
```

# Verifier input

```A
llocatedWire { Witness: Witness(3), AllocatedNum variable: Variable(Aux(3)), AllocatedNum value: None }
AllocatedWire { Witness: Witness(2), AllocatedNum variable: Variable(Aux(2)), AllocatedNum value: None }
AllocatedWire { Witness: Witness(4), AllocatedNum variable: Variable(Aux(4)), AllocatedNum value: None },
AllocatedWire { Witness: Witness(0), AllocatedNum variable: Variable(Aux(0)), AllocatedNum value: None }
AllocatedWire { Witness: Witness(1), AllocatedNum variable: Variable(Aux(1)), AllocatedNum value: None }}

# Decimal repr. from Sage script

```
G_x = 3
G_y = 40902200210088653215032584946694356296222563095503428277299570638400093548589
G + G = (10387378418920170991901925379757851472848140451366402977927462146922501327331 : 13820003873047333813317371183515203145343686146200578295967632643564487086665 : 1)
```

=> Witness values match