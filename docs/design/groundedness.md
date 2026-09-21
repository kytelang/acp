# Groundedness and hallucination detection

Date: 2026-09-21
Status: design and honest positioning. A baseline is implemented (`acp_core::groundedness`, the `GroundednessScorer`, and `acp groundedness`); this document records how the market does it, what ACP does, and the upgrade path, so the capability is positioned honestly.

## 1. The distinction that governs everything

There are two different problems, with very different reliability:

- Groundedness (contextual faithfulness): does the answer follow from a provided source (retrieved documents, tool results)? This is the mature, deployable capability. It only works when there is a source, that is, in RAG or tool-augmented flows.
- Reference-free factuality: is a free-standing claim true about the world, with no source supplied? This remains fundamentally unreliable. No serious product certifies it.

Every credible production detector is the first kind. ACP takes the same position: it does context-grounded groundedness, and it does not claim reference-free factuality.

## 2. How the market does it (2026)

The runtime AI-firewall vendors (Lakera, Prompt Security, Cisco AI Defense) do not detect hallucination at all; they remain focused on prompt-injection, data-leak and content safety. The capability lives in the model-platform guardrails, a few security products, and the observability and eval tools:

- Azure AI Content Safety groundedness detection: a proprietary classifier over (source, response) with a fast non-reasoning mode and a reasoning mode, plus an optional correction feature that rewrites ungrounded text. Requires grounding sources.
- AWS Bedrock Guardrails contextual grounding: a grounding score and a relevance score over (source, query, response), threshold-gated inline. Summarisation and QA only, not conversational.
- NVIDIA NeMo Guardrails: several output rails, self check facts (LLM-as-judge over evidence), alignscore check facts (a RoBERTa-based fine-tuned classifier), Patronus Lynx (a fine-tuned Llama-3 judge), and self check hallucination (SelfCheckGPT-style self-consistency, reference-free).
- Protect AI LLM Guard FactualConsistency (Palo Alto lineage): zero-shot NLI (DeBERTa) over (prompt, output), inline, millisecond-scale.
- Vectara HHEM-2.1: a small fine-tuned NLI classifier (T5) over (evidence, claim); powers a public hallucination leaderboard; runs locally.
- Patronus Lynx, Galileo Luna-2, Fiddler Centor models: fine-tuned small or mid models, context-grounded, some inline sub-100ms in a customer VPC.
- Cleanlab TLM: a reference-free trustworthiness score (self-reflection plus consistency), for triage not truth.
- RAGAS faithfulness, Arize Phoenix faithfulness and hallucination, WhyLabs LangKit: mostly offline evaluation and monitoring rather than inline blocking.

## 3. The techniques, and their tradeoffs

1. NLI or entailment groundedness (Vectara HHEM, AlignScore, LLM Guard DeBERTa). A cross-encoder over (evidence, claim) returns entailment or contradiction. Cheap, fast (milliseconds), local, deterministic. Needs source context; weaker on long or multi-hop evidence and numeric reasoning. Best for inline RAG checks on-premises.
2. LLM-as-judge or critic (NeMo self-check, Patronus Lynx, Galileo, Bedrock and Azure classifiers). Flexible and explainable; fine-tuned judges beat generic frontier models at lower cost. Adds latency and cost; the judge can itself hallucinate; needs fail-closed handling.
3. Self-consistency (SelfCheckGPT). Sample the model several times and measure agreement. Reference-free, but N times the cost and it detects instability, not truth: a confidently-wrong model passes.
4. Citation and attribution (Guardrails AI). Check each sentence is supported by a retrieved chunk via embedding similarity or an LLM. Needs sources; embedding similarity is not entailment.
5. Fine-tuned hallucination classifiers (HHEM, AlignScore, Lynx, Luna-2, Fiddler Centor). Best accuracy per dollar and low latency; distribution-bound and still context-dependent for the faithfulness variants.
6. Uncertainty and trustworthiness scoring (Cleanlab TLM, logprob signals). Reference-free and real-time; correlates with, but does not prove, factuality.

Consensus: grounded faithfulness is deployable; reference-free factuality is not reliably certifiable, and reputable vendors do not market it as such.

## 4. What ACP does

- Built baseline: `acp_core::groundedness` scores an answer against a source context by per-sentence content-word support (a lexical baseline), flags the unsupported sentences, and exposes it two ways: the `GroundednessScorer` behind the content Scorer seam (using a source field on the scan context), and the `acp groundedness <answer> <context>` command. It emits an "ungrounded" signal that blocks above a configurable threshold, and it runs only when a source context is present.
- Honest boundary: the baseline is lexical, not semantic. It catches an answer that invents content absent from the source, and it can flag a heavy paraphrase that reuses few source words (a false positive). It is a first cut, not a fine-tuned model.

## 5. The upgrade path (recommended, matches the market)

The Scorer seam means the detector can be upgraded without changing any caller:

- On-premises primary: a fine-tuned NLI or small-model groundedness scorer (HHEM-style T5 or AlignScore-style RoBERTa) exported to the same ONNX or Candle runtime the ML content engine uses. Millisecond-scale, local, air-gap friendly, and strong enough to gate inline. This is the recommended production detector for ACP's on-premises posture.
- Optional explainability tier: an LLM-as-judge (a fine-tuned judge such as Lynx) for cases that need a reasoned explanation, run asynchronously or for review rather than in the hot path.
- Claim decomposition: split the answer into claims (RAGAS-style) and ground each, for finer localisation.
- External integration: call Azure groundedness or Bedrock contextual grounding through the content-scan hook when a customer prefers a managed detector.
- Behaviour: inline block for the fast NLI or small-model tier; monitor-and-flag for the slower LLM-judge tier; fail-closed on evaluator errors.

## 6. Where this fits in ACP, and the honest caveat

Groundedness is a content-quality check, adjacent to ACP's core of authorization and evidence. The natural in-path insertion points are the model gateway (an answer against the context in its own request) and tool-result screening (a RAG or tool result against the query), each of which needs a per-application convention for what counts as the source context. That convention is the integration step; the CLI and the seam are usable today.

The honest caveat, consistent with the rest of ACP: detection is best-effort, and reference-free factuality is out of scope because it is not reliable for anyone. The layer that survives a wrong or fabricated model output is authorization: even if an answer is ungrounded, an unauthorised action it proposes is still blocked at the resource boundary, and every decision is recorded as verifiable evidence.
