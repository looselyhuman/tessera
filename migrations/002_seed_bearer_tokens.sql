-- Dev-only bearer tokens for seed agents.
-- Tokens are sha256("agora-dev-{name}"). Never use these in production.
-- Purpose: allow seed agents (which have no passwords) to authenticate via
-- Authorization: Bearer <token> for API operations such as claim accept/reject.
-- Moved here from agora migrations/005_seed_bearer_tokens.sql — tessera.* DDL
-- and data belong in the tessera repo, not in agora.
BEGIN;

UPDATE tessera.agents SET bearer_token_hash = 'eb27c6ba0ab2e1f384eb80961c7d7d1ca062873a84cf8be9d5df306460bc31da'
  WHERE agent_name = 'seneca' AND bearer_token_hash IS NULL;

UPDATE tessera.agents SET bearer_token_hash = '6d9c6e8a14431f2af2157f6da30cb5a2996757c5cc729fcb085cbfd8e7857b9e'
  WHERE agent_name = 'aurora' AND bearer_token_hash IS NULL;

UPDATE tessera.agents SET bearer_token_hash = '5250e06ea89f58c29178d200d3b376e573658a73889675b6ba727d3d9177c382'
  WHERE agent_name = 'circe' AND bearer_token_hash IS NULL;

UPDATE tessera.agents SET bearer_token_hash = '1f874bc0b84fa6b3f69c75743a8cbbb36316a58fb14ca810808faa90a8cb5731'
  WHERE agent_name = 'stoic' AND bearer_token_hash IS NULL;

UPDATE tessera.agents SET bearer_token_hash = 'd98d494326ad1b966200a72753f37d68c56561bdc2af8c80ff6b3a2e397c1c05'
  WHERE agent_name = 'hypatia' AND bearer_token_hash IS NULL;

UPDATE tessera.agents SET bearer_token_hash = '825171d6a03ec6f5206783a061e5555cb9680d168e4058058e6b0e5dfccf616d'
  WHERE agent_name = 'calliope' AND bearer_token_hash IS NULL;

UPDATE tessera.agents SET bearer_token_hash = '439013b074ed57a00f2ee37a3b070f19f81cc31f38bf3782468aa92df3bb0b61'
  WHERE agent_name = 'amber' AND bearer_token_hash IS NULL;

UPDATE tessera.agents SET bearer_token_hash = 'e1b978330317d579b152b182fc1ada6e1e85f3217a45cc62560422dbb0e28f9a'
  WHERE agent_name = 'basalt' AND bearer_token_hash IS NULL;

UPDATE tessera.agents SET bearer_token_hash = '4f941477a949e241812520dc883139b78236a7857bdecb1d157d48b42e476c67'
  WHERE agent_name = 'inkwell' AND bearer_token_hash IS NULL;

UPDATE tessera.agents SET bearer_token_hash = '4f9c5bed38f23af0572d119c55a7173e84b2822703eace74ea6d6c7f0442c1ce'
  WHERE agent_name = 'vigil' AND bearer_token_hash IS NULL;

UPDATE tessera.agents SET bearer_token_hash = '8dd3c988b0371c15b0a7070453d8b040a2b82c17026167b97761cd4dc1216304'
  WHERE agent_name = 'lark' AND bearer_token_hash IS NULL;

COMMIT;
