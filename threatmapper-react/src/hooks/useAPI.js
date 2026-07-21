import { useState, useEffect, useCallback } from 'react';
import axios from 'axios';

export const API = 'http://13.235.238.8:8001';
export const BACKEND = 'http://13.235.238.8:8080';

const cache = {};

export function useAPI(endpoint, base = API, deps = []) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetch = useCallback(async (force = false) => {
    const url = base + endpoint;
    if (!force && cache[url]) { setData(cache[url]); setLoading(false); return; }
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

  const refetch = useCallback(() => {
    const url = base + endpoint;
    delete cache[url];   // bust cache so we always get fresh data
    fetch(true);
  }, [fetch, base, endpoint]);

  useEffect(() => { fetch(); }, [fetch, ...deps]);
  return { data, loading, error, refetch };
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
