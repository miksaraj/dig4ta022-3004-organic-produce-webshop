import createPersistedState from 'vuex-persistedstate'

/**
 * Creates persisted state version of Vuex store
 * in localStorage in order to persist profile
 * and progress data in case of page refresh
 * and cache disabled (dev default conditions)
 */
export default ({ store }) => {
	createPersistedState({
		key: 'vuex',
		paths: ['profile', 'progress']
	})(store)
}
