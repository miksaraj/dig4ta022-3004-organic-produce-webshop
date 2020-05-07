<template>
	<div>
		<options-row :type="type" />
		<card-deck v-if="view === 'cards'" :items="items" :type="type" />
		<accordion-list v-if="view === 'list'" :items="items" />
	</div>
</template>

<script>
import { mapGetters } from 'vuex'
import OptionsRow from '~/components/OptionsRow.vue'
import CardDeck from '~/components/CardDeck.vue'
import AccordionList from '~/components/AccordionList.vue'
export default {
	components: {
		CardDeck,
		OptionsRow,
		AccordionList
	},
	data() {
		return {
			type: 'sections'
		}
	},
	computed: {
		...mapGetters('sections', ['sectionsByChapter']),
		items() {
			return this.sectionsByChapter(this.chapterId)
		},
		view() {
			return this.$store.state.settings.sectionsView
		},
		chapterId() {
			return parseInt(this.$route.params.id)
		}
	}
}
</script>
