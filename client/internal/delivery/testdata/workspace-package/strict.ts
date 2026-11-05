import { z } from 'zod';

export const languageSchema = z.enum(['javascript', 'typescript', 'python', 'java', 'go', 'rust', 'csharp']);
