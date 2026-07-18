import { useState, useEffect, useCallback } from 'react';
import axios from 'axios';

export const API = 'http://13.235.238.8:8001';
export const BACKEND = 'http://13.235.238.8:8080';

const cache = {};

export function useAPI(endpoint, base = API, deps = []) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetch = useCallback(async () => {
    const url = base + endpoint;
    if (cache[url]) { setData(cache[url]); setLoading(false); return; }
    setLoading(true);
    try {
      const res = await axios.get(url, { timeout: 8000 });
      cache[url] = res.data;
      setData(res.data);
      setError(null);
    } catch (e) {
      setError(e.message);
      console.warn('API failed:', url);
    } finally {
      setLoading(false);
    }
  }, [endpoint, base]);

  useEffect(() => { fetch(); }, [fetch, ...deps]);
  return { data, loading, error, refetch: fetch };
}

export async function apiFetch(endpoint, base = API) {
  try {
    const res = await axios.get(base + endpoint, { timeout: 8000 });
    return res.data;
  } catch (e) {
    console.warn('Fetch failed:', endpoint);
    return null;
  }
}
