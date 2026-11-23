# Decision 002: Milan and Genoa product selection

The `azure-snp-vtpm-ima/1` evidence contract remains unchanged. SNP report
versions 3 and 5 carry signed CPUID family/model fields. Family `0x19` models
`0x00–0x0f` select Milan; `0x10–0x1f` select Genoa. Model range
`0xa0–0xaf` is Siena, which shares Genoa root keys but is a distinct product
and remains unsupported. Other values fail closed. The untrusted
`inspect_requirements` result supplies a constrained
KDS selector, never a URL. Live callers require a present product selector to
match the locally selected verifier policy before making a KDS request.

For v3/v5, the verifier independently checks that the signed processor product
matches the policy. For every supported version, it checks that the VCEK product
extension is that product (with or without a stepping suffix), and that VCEK
chip ID and TCB match the signed report. The
product-specific ARK digest, minimum TCB, launch measurement and immutable IMA
reference remain local enrollments. SNP v2 lacks a CPUID selector, so historical
offline verification can still establish its product through the pinned policy
and authenticated VCEK. Live callers use the local policy product for v2 KDS
retrieval; they never infer it from absent CPUID fields. There is no claim for
other AMD products, VLEK, TDX or CCA.

On the current Genoa VM (SNP v5, family `0x19`, model `0x11`), an AMD KDS
chain and chip-specific VCEK verified a fresh report. With a local test
enrollment of the current boot/IMA state, all 12 stages returned `verified`.
An isolated application run admitted the matching evidence, denied a distinct
Genoa IMA/PCR reference, rejected cross-origin use and wrong TLS name/service
identity, and sent no application request in the denied case. Milan historical
replay passed all 28 cases. The local reference was derived from the observed
host, so these tests establish implementation behavior, **not** independent
approval of the host state. A reviewed, immutable Genoa reference and policy
must be published separately before using this enrollment for public admission.

The signed layout and product mapping follow AMD's [SNP ABI 1.58](https://www.amd.com/content/dam/amd/en/documents/developer/56860.pdf);
the [AMD VCEK/KDS specification](https://docs.amd.com/v/u/en-US/57230)
defines product-specific certificate retrieval and VCEK extensions.
