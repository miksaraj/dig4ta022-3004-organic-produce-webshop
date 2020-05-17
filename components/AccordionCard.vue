<template>
	<b-card no-body>
		<b-card-header role="tab">
			<b-button v-b-toggle="'accordion-' + item.id" block>
				{{ item.header }}
			</b-button>
		</b-card-header>
		<b-collapse
			:id="'accordion-' + item.id"
			accordion="accordion-list"
			role="tabpanel"
		>
			<b-card-body>
				<p>{{ item.description }}</p>
				<card-list-group
					:items="listItems"
					:type="type"
					:id="item.id"
				/>
				<progress-bar :item="item" />
			</b-card-body>
		</b-collapse>
	</b-card>
</template>

<style scoped>
.card-header .btn {
	background-color: var(--color-main);
}
</style>

<script>
import { mapGetters } from 'vuex'
import CardListGroup from '~/components/CardListGroup.vue'
import ProgressBar from '~/components/ProgressBar.vue'
export default {
	name: 'AccordionCard',
	components: {
		CardListGroup,
		ProgressBar
	},
	data() {
		return {
			listItems: []
		}
	},
	computed: {
		...mapGetters({
			sectionsByChapter: 'sections/sectionsByChapter',
			sectionStructure: 'structure/sectionStructure',
			contentBySection: 'content/contentBySection'
		}),
		item() {
			return this.$attrs.item
		},
		type() {
			return this.$attrs.type
		}
	},
	mounted() {
		this.getList()
	},
	methods: {
		getList() {
			if (this.type === 'chapters') {
				this.listItems = this.sectionsByChapter(this.item.id)
			} else {
				const content = this.sectionStructure(this.item.id)
				this.listItems = this.contentBySection(content)
			}
		}
	}
}
</script>
