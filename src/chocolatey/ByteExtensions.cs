// Copyright © 2011 - Present RealDimensions Software, LLC
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// 
// You may obtain a copy of the License at
// 
// 	http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

namespace chocolatey
{
    public static class ByteExtensions
    {
        /// <summary>
        /// Determines whether a byte array contains a given set of bytes.
        /// </summary>
        /// <param name="input">The byte array to search</param>
        /// <param name="search">The bytes to search for</param>
        /// <returns></returns>
        /// <remarks>
        /// Based on http://stackoverflow.com/a/283648/18475
        /// </remarks>
        public static bool contains(this byte[] input, byte[] search)
        {
            if (input == null
                || search == null
                || input.Length == 0
                || search.Length == 0
                || search.Length > input.Length) return false;

            for (int i = 0; i < input.Length; i++)
            {
                if (!is_match(input, i, search)) continue;

                return true;
            }

            return false;
        }

        private static bool is_match(byte[] array, int position, byte[] candidate)
        {
            if (candidate.Length > (array.Length - position)) return false;

            for (int i = 0; i < candidate.Length; i++)
            {
                if (array[position + i] != candidate[i]) return false;
            }

            return true;
        }
    }
}
