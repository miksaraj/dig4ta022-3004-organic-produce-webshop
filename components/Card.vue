<template>
	<b-card>
		<h2>
			<nuxt-link v-if="type === 'chapters'" :to="'/chapters/' + item.id">
				{{ item.header }}
			</nuxt-link>
			<nuxt-link
				v-else
				:to="'/chapters/' + $route.params.id + '/' + item.id"
			>
				{{ item.header }}
			</nuxt-link>
		</h2>
		<p>{{ item.description }}</p>
		<card-list-group :items="subItems" :type="type" />
		<template v-slot:footer>
			<progress-bar :item="item" :subItems="subItems" />
		</template>
	</b-card>
</template>

<style scoped>
.card {
	height: 95%;
	margin-bottom: 1rem;
	width: 24vw;
}
</style>

<script>
import { mapGetters } from 'vuex'
import CardListGroup from '~/components/CardListGroup.vue'
import ProgressBar from '~/components/ProgressBar.vue'
export default {
	name: 'Card',
	components: {
		CardListGroup,
		ProgressBar
	},
	data() {
		return {
			subItems: []
		}
	},
	computed: {
		...mapGetters('sections', ['sectionsByChapter']),
		item() {
			return this.$attrs.item
		},
		type() {
			return this.$attrs.type
		}
	},
	mounted() {
		// only for course modules for now
		if (this.type === 'chapters') {
			this.getSubItems()
		}
	},
	methods: {
		getSubItems() {
			this.subItems = this.sectionsByChapter(this.item.id)
		}
	}
}
</script>
